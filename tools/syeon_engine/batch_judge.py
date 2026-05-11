"""
batch_judge.py  (v7)
--------------------
규칙/LLM 하이브리드 판정 엔진.

변경사항 (v7):
  1. raw_output 2차 호출 비활성화 (include_raw 항상 False)
  2. 프롬프트 길이 대폭 축소 + 총 글자수 상한 제어 (MAX_PROMPT_CHARS)
  3. asyncio.Semaphore 기반 동시 호출 제어 (MAX_CONCURRENT)
  4. BATCH_SIZE 기본값 3으로 축소

흐름:
  1단계 규칙 엔진 → 분류
    ├─ 전체 미설치              → 즉시 해당없음 (LLM 없음)
    ├─ 규칙 확정 취약 (≥85)    → 즉시 취약 (LLM 없음)
    ├─ 규칙 확정 양호 (conclusive, <70) → 배치 LLM
    └─ 불확실                   → 개별 LLM

서비스 상태값:
  RUNNING / NOT_RUNNING / NOT_INSTALLED / INSTALLED / N/A
"""

import asyncio
import json
import os
import re
import sqlite3
import time as _time
from typing import Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types
from schemas import JudgePayload, JudgeResult

load_dotenv()

# ──────────────────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────────────────

GEMINI_MODEL_DEFAULT = "gemini-2.5-flash"


def _gemini_model() -> str:
    """매 호출 시 .env 변경이 반영되도록 런타임에 읽음."""
    return os.getenv("GEMINI_MODEL", GEMINI_MODEL_DEFAULT)

GEMINI_RETRY_DELAY = float(os.getenv("GEMINI_RETRY_DELAY", "65"))
GEMINI_MAX_RETRY   = int(os.getenv("GEMINI_MAX_RETRY",   "4"))
BATCH_SIZE         = int(os.getenv("BATCH_SIZE",         "3"))   # 확정양호 배치 크기 (할루시네이션 방지)
RULE_CERTAIN_VULN  = int(os.getenv("RULE_CERTAIN_VULN",  "85"))
GUIDELINE_DB_PATH  = os.getenv("GUIDELINE_DB_PATH",   "./db/guidelines.db")

# 동시 호출 제한 — 개별 항목은 순차(1)로, 버스트 방지
MAX_CONCURRENT     = int(os.getenv("MAX_CONCURRENT",  "1"))

# 프롬프트 총 글자수 상한 (초과 시 truncate) — Gemini 2.5 Flash 1M 토큰 고려하여 넉넉히
MAX_PROMPT_CHARS   = int(os.getenv("MAX_PROMPT_CHARS", "8000"))

# RPM / TPM 상한 (Rate Limiter)
MAX_RPM            = int(os.getenv("MAX_RPM",   "9"))
MAX_TPM            = int(os.getenv("MAX_TPM",   "200000"))
REQUEST_MIN_DELAY  = float(os.getenv("REQUEST_MIN_DELAY", "7.0"))  # 10 RPM 안전마진
PROMPT_DUMP_FILE   = os.getenv("PROMPT_DUMP_FILE", "/tmp/syeon_prompts_latest.txt")

SCORE_WEIGHT_RULE  = 0.30
SCORE_WEIGHT_LLM   = 0.70
THRESHOLD_VULN     = 70
THRESHOLD_OK       = 40


def _get_api_key() -> str:
    return os.getenv("GEMINI_API_KEY") or ""


# ──────────────────────────────────────────────────────────
# Rate Limiter (모듈 레벨)
# ──────────────────────────────────────────────────────────

_rl_window:    list  = []
_rl_tpm_used:  int   = 0
_rl_tpm_reset: float = 0.0


async def _rate_limit_wait(estimated_tokens: int = 2000):
    """RPM / TPM 한도 초과 예상 시 다음 분까지 대기."""
    global _rl_window, _rl_tpm_used, _rl_tpm_reset

    now = _time.time()
    _rl_window = [t for t in _rl_window if now - t < 60]

    if now - _rl_tpm_reset >= 60:
        _rl_tpm_used  = 0
        _rl_tpm_reset = now

    # RPM 체크
    if len(_rl_window) >= MAX_RPM:
        wait = 61 - (now - _rl_window[0])
        if wait > 0:
            print(f"    [RateLimit] RPM {len(_rl_window)}/{MAX_RPM} → {wait:.0f}초 대기")
            await asyncio.sleep(wait)
            now = _time.time()
            _rl_window = [t for t in _rl_window if now - t < 60]

    # TPM 체크
    if _rl_tpm_used + estimated_tokens > MAX_TPM:
        wait = 61 - (now - _rl_tpm_reset)
        if wait > 0:
            print(f"    [RateLimit] TPM {_rl_tpm_used}/{MAX_TPM} → {wait:.0f}초 대기")
            await asyncio.sleep(wait)
            _rl_tpm_used  = 0
            _rl_tpm_reset = _time.time()

    if REQUEST_MIN_DELAY > 0:
        await asyncio.sleep(REQUEST_MIN_DELAY)
    _rl_window.append(_time.time())
    _rl_tpm_used += estimated_tokens


# ──────────────────────────────────────────────────────────
# 가이드라인 DB
# ──────────────────────────────────────────────────────────

class _DB:
    _cache: dict = {}

    @classmethod
    def get(cls, code: str) -> dict:
        if code in cls._cache:
            return cls._cache[code]
        db_path = os.getenv("GUIDELINE_DB_PATH", GUIDELINE_DB_PATH)
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM guidelines WHERE item_code=?", (code,)
            ).fetchone()
            conn.close()
            cls._cache[code] = dict(row) if row else {}
        except Exception:
            cls._cache[code] = {}
        return cls._cache[code]

    @classmethod
    def vuln_kw(cls, code: str) -> list[str]:
        return [k.strip().lower()
                for k in cls.get(code).get("vuln_keywords", "").split(",") if k.strip()]

    @classmethod
    def ok_kw(cls, code: str) -> list[str]:
        return [k.strip().lower()
                for k in cls.get(code).get("ok_keywords", "").split(",") if k.strip()]

    @classmethod
    def standard(cls, code: str) -> str:
        g = cls.get(code)
        parts = []
        if g.get("standard"):  parts.append(g["standard"])
        if g.get("severity"):  parts.append(f"위험도:{g['severity']}")
        return " | ".join(parts) if parts else "가이드라인 없음"

    @classmethod
    def check_point(cls, code: str) -> str:
        return (cls.get(code).get("check_point") or "").strip()

    @classmethod
    def remediation(cls, code: str) -> str:
        return (cls.get(code).get("remediation") or "수동 확인 필요").strip()

    @classmethod
    def severity(cls, code: str) -> str:
        return (cls.get(code).get("severity") or "").strip()

    @classmethod
    def category(cls, code: str) -> str:
        return (cls.get(code).get("category") or "").strip()


# ──────────────────────────────────────────────────────────
# 구조적 패턴 헬퍼
# ──────────────────────────────────────────────────────────

def _parse_permission(cv: str) -> dict:
    m = re.search(r'^[-dlcbps]([rwxsStT-]{3})([rwxsStT-]{3})([rwxsStT-]{3})', cv.strip())
    if not m:
        return {}
    return {
        "owner": m.group(1), "group": m.group(2), "other": m.group(3),
        "suid":        's' in m.group(1).lower(),
        "world_write": 'w' in m.group(3),
        "world_read":  'r' in m.group(3),
        "group_write": 'w' in m.group(2),
    }


def _count_found(cv: str) -> int:
    for pat in [r'(\d+)\s*개\s*발견', r'(\d+)\s*found', r'Hidden\s+\w+:\s*(\d+)']:
        m = re.search(pat, cv, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return -1


_ABSENT_PATTERNS = [
    "file not found", "파일 없음", "파일이 존재하지 않음",
    "not found", "(없음)", "설정 없음",
]

_SAFE_CONFIG_WORDS = [
    "no", "deny", "false", "0", "disable", "off",
    "none", "inactive", "prohibit", "closed",
]


# ──────────────────────────────────────────────────────────
# 규칙 엔진
# ──────────────────────────────────────────────────────────

def _rule_score(payload: JudgePayload) -> tuple[int, str, bool]:
    """
    반환: (score 0~100, reason, is_conclusive)
    score == -1 → 전체 미설치 (해당없음 마커)
    """
    checks = payload.check_results
    code   = payload.item_code
    vkws   = _DB.vuln_kw(code)
    okws   = _DB.ok_kw(code)

    # ── 전역 확정: 전체 미설치 ─────────────────────────────
    if checks and all(c.service_status.upper() == "NOT_INSTALLED" for c in checks):
        return -1, "전체 서비스/패키지 미설치", True

    # ── 전역 확정: 서비스 체크 전체 비활성+파일없음 ────────
    svc_checks = [c for c in checks if c.service_status.upper() != "N/A"]
    if svc_checks:
        all_absent = all(
            c.service_status.upper() in ("NOT_INSTALLED", "NOT_RUNNING")
            and any(pat in c.collected_value.lower() for pat in _ABSENT_PATTERNS)
            for c in svc_checks
        )
        if all_absent:
            return 0, "관련 서비스 비활성 및 대상 파일 없음", True

    total, reasons = 0, []

    for c in checks:
        cv   = c.collected_value or ""
        comb = cv.lower()
        svc  = c.service_status.upper()
        sub  = c.sub_check[:18]

        # Step 1: 서비스 상태
        if svc == "NOT_INSTALLED":
            total -= 25; reasons.append(f"{sub}:미설치(-25)"); continue
        if svc == "NOT_RUNNING":
            total -= 25; reasons.append(f"{sub}:미실행(-25)")
        elif svc == "RUNNING":
            total += 10; reasons.append(f"{sub}:실행중(+10)")
        elif svc == "INSTALLED":
            total += 5;  reasons.append(f"{sub}:설치됨(+5)")

        # Step 2: 파일/설정 없음
        if any(pat in comb for pat in _ABSENT_PATTERNS + ["권한 없음"]):
            if svc in ("NOT_RUNNING", "NOT_INSTALLED"):
                reasons.append(f"{sub}:서비스없음→파일없음(무시)")
            else:
                total += 15; reasons.append(f"{sub}:파일/설정없음(+15)")
            continue

        # Step 3: nouser/nogroup
        if re.search(r'\bnouser\b|\bnogroup\b', comb):
            total += 10; reasons.append(f"{sub}:nouser/nogroup(+10)")

        # Step 4: ls -la 권한
        perm = _parse_permission(cv)
        if perm:
            if perm.get("world_write"):
                total += 20; reasons.append(f"{sub}:world_write(+20)")
            elif perm.get("group_write"):
                total += 10; reasons.append(f"{sub}:group_write(+10)")
            elif perm.get("world_read"):
                total += 10; reasons.append(f"{sub}:world_read(+10)")
            else:
                total -= 10; reasons.append(f"{sub}:권한양호(-10)")
            if not re.search(r'\broot\b', cv):
                total += 15; reasons.append(f"{sub}:비root소유(+15)")
            continue

        # Step 5: N개 발견
        found_n = _count_found(cv)
        if found_n >= 0:
            if found_n == 0:
                total -= 20; reasons.append(f"{sub}:발견없음(-20)")
            elif found_n <= 5:
                total += 20; reasons.append(f"{sub}:{found_n}개발견(+20)")
            else:
                total += 35; reasons.append(f"{sub}:{found_n}개발견(+35)")
            continue

        # Step 6: shadow 패스워드
        if re.search(r'[a-z_][a-z0-9_-]*:x:\d+:\d+:', comb):
            total -= 20; reasons.append(f"{sub}:shadow패스워드(-20)"); continue

        # Step 7: RUNNING + 안전설정 없음
        if svc == "RUNNING" and not any(k in comb for k in _SAFE_CONFIG_WORDS):
            total += 20; reasons.append(f"{sub}:실행+제한없음(+20)")

        # Step 8: DB 키워드
        matched = False
        for kw in vkws:
            if kw in comb:
                total += 40; reasons.append(f"{sub}:취약kw[{kw[:8]}](+40)")
                matched = True; break
        if not matched:
            for kw in okws:
                if kw in comb:
                    total -= 30; reasons.append(f"{sub}:양호kw[{kw[:8]}](-30)")
                    break

    total = max(0, min(100, total))
    return total, " | ".join(reasons) or "규칙매칭없음", False


# ──────────────────────────────────────────────────────────
# 프롬프트 빌더 (간결 버전 + 글자수 상한)
# ──────────────────────────────────────────────────────────

def _truncate(text: str, limit: int) -> str:
    return text[:limit] + "…" if len(text) > limit else text


def _build_single_prompt(payload: JudgePayload, rule_score: int) -> str:
    """
    raw_output 미포함.
    총 글자수 MAX_PROMPT_CHARS 이하로 제한.
    """
    code  = payload.item_code
    g_std = _DB.standard(code)
    g_cp  = _DB.check_point(code)

    g_rem = _DB.remediation(code)

    # OS 계열 감지 (remediation에서 명령어 선택 기준)
    os_name = payload.os_name or ""
    if any(k in os_name.lower() for k in ("debian", "ubuntu")):
        os_hint = "Debian/Ubuntu"
    elif any(k in os_name.lower() for k in ("rhel", "centos", "rocky", "alma")):
        os_hint = "RHEL 계열"
    else:
        os_hint = os_name or "Linux"

    # 헤더
    header = (
        f"항목:{code} {payload.item_name}\n"
        f"OS:{os_hint} | 규칙점수:{rule_score}\n"
        f"기준:{_truncate(g_std, 500)}\n"
    )
    if g_cp:
        header += f"점검:{_truncate(g_cp, 300)}\n"
    if g_rem and g_rem not in ("수동 확인 필요", ""):
        header += f"가이드라인조치:{_truncate(g_rem, 300)}\n"

    # sub_check 블록
    check_blocks = []
    for c in payload.check_results:
        cv = _truncate((c.collected_value or "(없음)").replace("\n", " "), 800)
        block = (
            f"[{c.sub_check[:40]}] svc={c.service_status}\n"
            f" val={cv}\n"
            f" cmd={c.source_command[:200]}"
        )
        check_blocks.append(block)

    body = "\n".join(check_blocks)

    # 총 글자수 제한
    full = header + body
    if len(full) > MAX_PROMPT_CHARS:
        full = full[:MAX_PROMPT_CHARS] + "\n(truncated)"

    return full


def _build_batch_prompt(batch: list, rule_scores: dict) -> str:
    lines = [f"{len(batch)}개 항목:"]
    for p in batch:
        code  = p.item_code
        g_std = _DB.standard(code)
        rs    = rule_scores.get(code, -1)
        item_lines = [
            f"[{code}] {p.item_name} rule={rs}",
            f" 기준:{_truncate(g_std, 300)}",
        ]
        for c in p.check_results:
            cv = _truncate((c.collected_value or "(없음)").replace("\n", " "), 300)
            item_lines.append(f" ·{c.sub_check[:30]}[{c.service_status}]:{cv}")
        lines.append("\n".join(item_lines))

    body = "\n\n".join(lines)
    if len(body) > MAX_PROMPT_CHARS * BATCH_SIZE:
        body = body[:MAX_PROMPT_CHARS * BATCH_SIZE] + "\n(truncated)"
    return body + f"\n\n위 {len(batch)}항목 JSON 배열:"


# ──────────────────────────────────────────────────────────
# 시스템 프롬프트 (간결)
# ──────────────────────────────────────────────────────────

SINGLE_SYSTEM = (
    "주통기 보안 점검 전문가. JSON 객체 하나만 출력.\n"
    '{"item_code":"U-XX","vuln_score":0~100,"result":"취약|양호|해당없음",'
    '"reason":"3~4줄: ①수집된 실제값 직접 인용 ②주통기 기준과 비교 ③취약/양호 근거 ④영향 또는 현황 요약",'
    '"remediation":"2~3줄: 현재 OS(Debian/Ubuntu 또는 RHEL 등)에 맞는 구체적 명령어 포함. 불필요 서비스는 systemctl disable/stop, 파일권한은 chmod/chown, 설정은 파일경로와 파라미터 명시"}\n'
    "판정순서: ①service_status ②collected_value→주통기기준비교 ③종합\n"
    "NOT_INSTALLED→해당없음 | NOT_RUNNING→양호우선 | N/A→파일/설정값만 판단\n"
    "80+취약 50~79취약가능 20~49양호가능 0~19양호"
)

BATCH_SYSTEM = (
    "주통기 보안 점검 전문가. JSON 배열만 출력 (입력 항목 순서 반드시 유지).\n"
    '[{"item_code":"U-XX","vuln_score":0~100,"result":"취약|양호|해당없음",'
    '"reason":"3줄: 해당 항목 실제 수집값 인용·기준 비교·근거 명시",'
    '"remediation":"1~2줄: 현재 OS 환경 기준 구체적 명령어 포함"},...]\n'
    "NOT_INSTALLED/NOT_RUNNING→해당없음 우선 | 80+취약 0~19양호\n"
    "★ 각 항목은 해당 항목 데이터만 참조 — 다른 항목 데이터 절대 혼용 금지"
)


# ──────────────────────────────────────────────────────────
# JSON 파싱
# ──────────────────────────────────────────────────────────

def _parse_single_json(raw: str) -> dict:
    if not raw or not raw.strip():
        return {}
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    try:
        d = json.loads(cleaned)
        return d[0] if isinstance(d, list) and d else (d if isinstance(d, dict) else {})
    except json.JSONDecodeError:
        pass
    s, e = cleaned.find("{"), cleaned.rfind("}") + 1
    if s != -1 and e > s:
        try:
            d = json.loads(cleaned[s:e])
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            pass
    result = {}
    for fname, pat in [
        ("vuln_score",  r'"vuln_score"\s*:\s*(\d+)'),
        ("result",      r'"result"\s*:\s*"([^"]+)"'),
        ("reason",      r'"reason"\s*:\s*"((?:[^"\\]|\\.){0,300})"'),
        ("remediation", r'"remediation"\s*:\s*"((?:[^"\\]|\\.){0,200})"'),
    ]:
        m = re.search(pat, cleaned, re.DOTALL)
        if m:
            v = m.group(1)
            result[fname] = int(v) if fname == "vuln_score" else v
    return result


def _parse_batch_json(raw: str, batch: list) -> list:
    if not raw or not raw.strip():
        return [{}] * len(batch)
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    s, e = cleaned.find("["), cleaned.rfind("]") + 1
    if s != -1 and e > s:
        try:
            data = json.loads(cleaned[s:e])
            if isinstance(data, list):
                while len(data) < len(batch): data.append({})
                return data[:len(batch)]
        except json.JSONDecodeError:
            pass
    results = []
    depth, start = 0, -1
    for i, ch in enumerate(cleaned):
        if ch == "{":
            if depth == 0: start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                try:
                    obj = json.loads(cleaned[start:i + 1])
                    if isinstance(obj, dict) and ("item_code" in obj or "vuln_score" in obj):
                        results.append(obj)
                except json.JSONDecodeError:
                    pass
                start = -1
    while len(results) < len(batch): results.append({})
    return results[:len(batch)]


# ──────────────────────────────────────────────────────────
# Gemini 호출 (Semaphore 적용)
# ──────────────────────────────────────────────────────────

_semaphore: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    return _semaphore


async def _call_single_item(
    client, payload: JudgePayload, rule_score: int, label: str
) -> dict:
    """raw_output 2차 호출 비활성화 — collected_value 기반 판정만."""
    prompt = _build_single_prompt(payload, rule_score)
    try:
        with open(PROMPT_DUMP_FILE, "a", encoding="utf-8") as _pf:
            _pf.write(f"\n{'='*60}\n[{payload.item_code}] {payload.item_name}\n[SYSTEM]\n{SINGLE_SYSTEM}\n[USER]\n{prompt}\n")
    except Exception:
        pass
    est_tokens = max(500, len(prompt) // 3 + 400)

    async with _get_semaphore():
        for attempt in range(1, GEMINI_MAX_RETRY + 1):
            await _rate_limit_wait(estimated_tokens=est_tokens)
            try:
                resp = await client.aio.models.generate_content(
                    model=_gemini_model(),
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SINGLE_SYSTEM,
                        temperature=0.1,
                        max_output_tokens=400,
                        thinking_config=types.ThinkingConfig(thinking_budget=0),
                    ),
                )
                raw = (resp.text or "") if hasattr(resp, "text") else ""
                if not raw.strip():
                    print(f"    [경고] {payload.item_code} 빈응답 → 재시도({attempt})")
                    continue

                parsed = _parse_single_json(raw)
                if parsed:
                    return parsed
                print(f"    [경고] {payload.item_code} 파싱실패({attempt}): {raw[:60]!r}")

            except Exception as e:
                err = str(e)
                if "429" in err or "RESOURCE_EXHAUSTED" in err:
                    wait = min(120, GEMINI_RETRY_DELAY * (2 ** (attempt - 1)))
                    print(f"    [429] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
                    await asyncio.sleep(wait)
                else:
                    print(f"    [오류] {label}: {err}")
                    return {}

    print(f"    [실패] {label} 재시도 초과")
    return {}


async def _call_batch(
    client, batch: list, rule_scores: dict, label: str
) -> list:
    prompt = _build_batch_prompt(batch, rule_scores)
    try:
        codes = ",".join(p.item_code for p in batch)
        with open(PROMPT_DUMP_FILE, "a", encoding="utf-8") as _pf:
            _pf.write(f"\n{'='*60}\n[BATCH: {codes}]\n[SYSTEM]\n{BATCH_SYSTEM}\n[USER]\n{prompt}\n")
    except Exception:
        pass
    est_tokens = max(800, len(prompt) // 3 + 300 * len(batch))

    async with _get_semaphore():
        for attempt in range(1, GEMINI_MAX_RETRY + 1):
            await _rate_limit_wait(estimated_tokens=est_tokens)
            try:
                resp = await client.aio.models.generate_content(
                    model=_gemini_model(),
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=BATCH_SYSTEM,
                        temperature=0.1,
                        max_output_tokens=350 * len(batch),
                        thinking_config=types.ThinkingConfig(thinking_budget=0),
                    ),
                )
                raw = (resp.text or "") if hasattr(resp, "text") else ""
                if not raw.strip():
                    print(f"    [경고] {label} 빈응답 → 재시도({attempt})")
                    continue
                return _parse_batch_json(raw, batch)

            except Exception as e:
                err = str(e)
                if "429" in err or "RESOURCE_EXHAUSTED" in err:
                    wait = min(120, GEMINI_RETRY_DELAY * (2 ** (attempt - 1)))
                    print(f"  [429] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
                    await asyncio.sleep(wait)
                else:
                    print(f"  [오류] {label}: {err}")
                    return [{}] * len(batch)

    print(f"  [실패] {label} 재시도 초과")
    return [{}] * len(batch)


# ──────────────────────────────────────────────────────────
# 최종 판정 조합
# ──────────────────────────────────────────────────────────

def _finalize(
    payload: JudgePayload, rule_score: int, rule_reason: str,
    llm_data: dict, mode: str
) -> JudgeResult:
    code      = payload.item_code
    llm_score = int(llm_data.get("vuln_score", 50)) if llm_data else -1

    if mode == "rule_only" or not llm_data:
        final_score = rule_score
        reason      = f"[규칙] {rule_reason}"
        remediation = _DB.remediation(code)
    elif mode == "llm_only":
        final_score = llm_score if llm_score != -1 else 50
        reason      = f"[LLM] {llm_data.get('reason', '')}"
        remediation = llm_data.get("remediation", "수동 확인 필요")
    else:  # hybrid
        if llm_score == -1:
            final_score = rule_score
            reason      = f"[규칙] {rule_reason} (LLM실패→규칙대체)"
            remediation = _DB.remediation(code)
        else:
            final_score = round(
                rule_score * SCORE_WEIGHT_RULE + llm_score * SCORE_WEIGHT_LLM
            )
            note   = f"(규칙{rule_score}×0.3+LLM{llm_score}×0.7={final_score})"
            reason = (
                f"[규칙] {rule_reason} | "
                f"[LLM] {llm_data.get('reason', '')} | {note}"
            )
            remediation = llm_data.get("remediation", "수동 확인 필요")

    # LLM 해당없음 명시 → 우선 적용
    if llm_data and llm_data.get("result") == "해당없음":
        return _make_result(
            payload, code, "해당없음",
            f"[LLM] {llm_data.get('reason', '해당없음')}",
            "해당 없음", 0.9, mode
        )

    # 점수 → 결과
    if final_score >= THRESHOLD_VULN:
        result = "취약"
        conf   = round(min(1.0, final_score / 100), 2)
    elif final_score < THRESHOLD_OK:
        result = "양호"
        conf   = round(min(1.0, (100 - final_score) / 100), 2)
    else:
        result = "취약"
        conf   = 0.5
        reason = f"[검토필요→취약] {reason}"

    reason = " | ".join(reason.split(" | ")[:4])
    return _make_result(payload, code, result, reason, remediation, conf, mode)


def _make_result(
    payload, code, result, reason, remediation, confidence, mode
) -> JudgeResult:
    try:
        collected_json = json.dumps(
            [{"sub_check": c.sub_check, "config_file": c.config_file,
              "collected_value": c.collected_value,
              "service_status": c.service_status,
              "source_command": c.source_command}
             for c in payload.check_results],
            ensure_ascii=False
        )
    except Exception:
        collected_json = "[]"

    return JudgeResult(
        scan_id       = payload.scan_id,
        item_code     = code,
        item_name     = payload.item_name,
        guideline_ref = f"주통기 Unix 서버 {code}",
        result        = result,
        reason        = reason,
        remediation   = remediation,
        confidence    = confidence,
        os_name       = getattr(payload, "os_name", ""),
        category      = _DB.category(code) or getattr(payload, "category", ""),
        severity      = _DB.severity(code),
        judge_mode    = mode,
        collected_json= collected_json,
    )


# ──────────────────────────────────────────────────────────
# BatchJudge — 공개 API
# ──────────────────────────────────────────────────────────

class BatchJudge:
    """
    사용법:
        results = asyncio.run(BatchJudge.run(payloads, mode="hybrid"))

    judge_mode:
        "hybrid"    규칙×0.3 + LLM×0.7  (기본)
        "rule_only" LLM 없음
        "llm_only"  규칙 무시
    """

    @staticmethod
    async def run(
        payloads: list,
        api_key: Optional[str] = None,
        mode: str = "hybrid",
    ) -> list:
        global _semaphore
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        global _rl_window, _rl_tpm_used, _rl_tpm_reset
        _rl_window     = []
        _rl_tpm_used   = 0
        _rl_tpm_reset  = _time.time()
        _DB._cache.clear()
        scan_id_for_dump = os.getenv("SCAN_ID", "unknown")
        try:
            with open(PROMPT_DUMP_FILE, "w", encoding="utf-8") as _pf:
                _pf.write(f"# 프롬프트 덤프 — scan_id={scan_id_for_dump}\n")
        except Exception:
            pass

        if not api_key:
            api_key = _get_api_key()

        # ── 1단계: 규칙 분류 ──────────────────────────────────
        not_installed:   list = []
        certain:         list = []
        confirmed_ok:    list = []
        need_individual: list = []
        rule_map:        dict = {}

        for p in payloads:
            score, reason, conclusive = _rule_score(p)
            rule_map[p.item_code] = (score, reason)

            if mode == "rule_only":
                certain.append((p, score, reason))
            elif score == -1:
                not_installed.append((p, reason))
            elif conclusive and score >= RULE_CERTAIN_VULN:
                certain.append((p, score, reason))
            elif conclusive and score < THRESHOLD_VULN:
                confirmed_ok.append(p)
            else:
                need_individual.append(p)

        n_ok_batches  = (len(confirmed_ok) + BATCH_SIZE - 1) // BATCH_SIZE
        n_llm_calls   = n_ok_batches + len(need_individual)
        eta = n_llm_calls * 15

        print(
            f"[BatchJudge] mode={mode} | model={_gemini_model()}\n"
            f"  전체={len(payloads)} | 미설치={len(not_installed)} | "
            f"확정취약={len(certain)} | "
            f"확정양호(배치)={len(confirmed_ok)}({n_ok_batches}배치) | "
            f"개별LLM={len(need_individual)}\n"
            f"  MAX_CONCURRENT={MAX_CONCURRENT} BATCH_SIZE={BATCH_SIZE} "
            f"MAX_PROMPT_CHARS={MAX_PROMPT_CHARS}\n"
            f"  예상≈{eta:.0f}초({eta/60:.1f}분)"
        )

        results: list = []

        # ── 2단계: 미설치 → 해당없음 ─────────────────────────
        for p, reason in not_installed:
            r = _finalize(p, 0, reason, {"result": "해당없음", "reason": reason}, mode)
            results.append(r)
            print(f"  [해당없음] {p.item_code} (미설치)")

        # ── 3단계: 확정 취약 즉시 처리 ───────────────────────
        for p, score, reason in certain:
            r = _finalize(p, score, reason, {}, mode)
            results.append(r)
            print(f"  [확정취약] {p.item_code}({score}점)")

        if not (confirmed_ok or need_individual) or not api_key:
            if not api_key and (confirmed_ok or need_individual):
                print("[BatchJudge] API KEY 없음 → 규칙 점수로 대체")
            for p in confirmed_ok + need_individual:
                score, reason = rule_map[p.item_code]
                results.append(_finalize(p, score, reason, {}, "rule_only"))
            _print_summary(results)
            return results

        client = genai.Client(api_key=api_key)
        rule_scores_map = {c: s for c, (s, _) in rule_map.items()}

        # ── 4단계: 확정 양호 → 배치 LLM (순차) ──────────────
        if confirmed_ok:
            print(f"\n[배치LLM] {len(confirmed_ok)}건 ({n_ok_batches}배치)...")
            for bi, bs in enumerate(range(0, len(confirmed_ok), BATCH_SIZE)):
                batch = confirmed_ok[bs:bs + BATCH_SIZE]
                codes = ",".join(p.item_code for p in batch)
                label = f"배치{bi+1}/{n_ok_batches}[{codes}]"
                print(f"  {label}")
                batch_out = await _call_batch(client, batch, rule_scores_map, label)
                for p, llm_d in zip(batch, batch_out):
                    score, reason = rule_map[p.item_code]
                    r = _finalize(p, score, reason, llm_d or {}, mode)
                    results.append(r)
                    vs = (llm_d or {}).get("vuln_score", "N/A")
                    print(f"    {p.item_code}: 규칙={score} LLM={vs} → {r.result}({r.confidence:.0%})")

        # ── 5단계: 불확실 → 개별 LLM (순차, MAX_CONCURRENT=1로 버스트 방지) ─
        if need_individual:
            print(f"\n[개별LLM] {len(need_individual)}건 (순차 처리)...")
            for idx, p in enumerate(need_individual, 1):
                score, reason = rule_map[p.item_code]
                label = f"개별{idx}/{len(need_individual)}[{p.item_code}]"
                print(f"  {label}")
                llm_d = await _call_single_item(client, p, score, label)
                r = _finalize(p, score, reason, llm_d or {}, mode)
                results.append(r)
                vs = (llm_d or {}).get("vuln_score", "N/A")
                print(f"    {p.item_code}: 규칙={score} LLM={vs} → {r.result}({r.confidence:.0%})")

        # 원래 순서 복원
        order = {p.item_code: i for i, p in enumerate(payloads)}
        results.sort(key=lambda r: order.get(r.item_code, 999))
        _print_summary(results)
        return results


def _print_summary(results: list):
    vuln = sum(1 for r in results if r.result == "취약")
    ok   = sum(1 for r in results if r.result == "양호")
    na   = sum(1 for r in results if r.result == "해당없음")
    print(f"\n[BatchJudge] 완료: 전체={len(results)} 취약={vuln} 양호={ok} 해당없음={na}")


# ──────────────────────────────────────────────────────────
# 디버그: 프롬프트 출력 (LLM 호출 없음)
# ──────────────────────────────────────────────────────────

def debug_print_prompt(payload: JudgePayload):
    score, reason, conclusive = _rule_score(payload)
    print("=" * 70)
    print(f"[디버그] {payload.item_code} | 규칙점수={score} | conclusive={conclusive}")
    print(f"[디버그] 규칙판단: {reason}")
    print("=" * 70)
    print("[SYSTEM PROMPT]")
    print(SINGLE_SYSTEM)
    print("-" * 70)
    print("[USER PROMPT]")
    print(_build_single_prompt(payload, score))
    print(f"\n[글자수: {len(_build_single_prompt(payload, score))} / {MAX_PROMPT_CHARS}]")
    print("=" * 70)


def debug_print_batch_prompt(payloads: list):
    rule_scores = {}
    for p in payloads:
        score, reason, _ = _rule_score(p)
        rule_scores[p.item_code] = score
        print(f"[규칙] {p.item_code}: score={score} | {reason}")
    print("=" * 70)
    print("[BATCH SYSTEM PROMPT]")
    print(BATCH_SYSTEM)
    print("-" * 70)
    print("[BATCH USER PROMPT]")
    prompt = _build_batch_prompt(payloads, rule_scores)
    print(prompt)
    print(f"\n[글자수: {len(prompt)} / {MAX_PROMPT_CHARS * BATCH_SIZE}]")
    print("=" * 70)
