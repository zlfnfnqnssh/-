"""
batch_judge.py  (v6)
--------------------
규칙/LLM 하이브리드 판정 엔진.

흐름:
  1단계 규칙 엔진 → 분류
    ├─ 규칙 확정 취약 (점수 ≥ RULE_CERTAIN_VULN)  → 즉시 확정
    ├─ 규칙 확정 양호 (conclusive, 점수 < 70)       → 배치 LLM 검증
    └─ 불확실 / 취약 가능성                         → 개별 LLM (가이드라인 전문)

서비스 상태값 (표준):
  RUNNING        → 서비스 실행 중
  NOT_RUNNING    → 설치됨, 중지 상태
  NOT_INSTALLED  → 미설치
  INSTALLED      → 설치됨(파일/설정 존재), 데몬 가동 불명
  N/A            → 서비스 무관 (파일 권한/설정값 체크)

규칙 엔진 설계 원칙:
  - 항목 코드(U-XX) 하드코딩 없음
  - 파일명 하드코딩 없음 → DB vuln_keywords/ok_keywords 의존
  - 구조적 패턴(ls -la, count, shadow:x:) 은 유닉스 범용이므로 유지
  - service_status 를 sub_check별 1차 신호로 사용
"""

import asyncio
import json
import os
import re
import sqlite3
from dataclasses import asdict
from typing import Optional

from google import genai
from google.genai import types
from schemas import JudgePayload, JudgeResult

# ──────────────────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────────────────

GEMINI_MODEL         = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_REQUEST_DELAY = float(os.getenv("GEMINI_REQUEST_DELAY", "20"))   # 무료티어 안전 간격 (15 RPM)
GEMINI_RETRY_DELAY   = float(os.getenv("GEMINI_RETRY_DELAY", "60"))     # 429 시 대기 (최대 90s cap)
GEMINI_MAX_RETRY     = int(os.getenv("GEMINI_MAX_RETRY", "3"))
BATCH_SIZE           = int(os.getenv("BATCH_SIZE", "10"))
RULE_CERTAIN_VULN    = int(os.getenv("RULE_CERTAIN_VULN", "85"))
GUIDELINE_DB_PATH    = os.getenv("GUIDELINE_DB_PATH", "./db/guidelines.db")

# 단순화된 규칙 엔진(서비스 상태만)은 최고 25점 수준 → LLM에 더 많은 가중치 부여
SCORE_WEIGHT_RULE = 0.3
SCORE_WEIGHT_LLM  = 0.7
THRESHOLD_VULN    = 60   # 이 이상 → 취약
THRESHOLD_OK      = 30   # 이 미만 → 양호 (중간 30~60 → 취약(50%) 검토필요)

MAX_RPM = int(os.getenv("MAX_RPM", "14"))   # 분당 최대 요청 수 (무료 15RPM 기준 여유 1개)
MAX_TPM = int(os.getenv("MAX_TPM", "900000"))  # 분당 최대 토큰 (무료 1M TPM이면 900000)

def _get_api_key() -> str:
    return os.getenv("GEMINI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or ""


# ──────────────────────────────────────────────────────────
# 가이드라인 DB
# ──────────────────────────────────────────────────────────

class _DB:
    _cache: dict = {}

    @classmethod
    def get(cls, code: str) -> dict:
        if code in cls._cache:
            return cls._cache[code]
        try:
            conn = sqlite3.connect(GUIDELINE_DB_PATH)
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM guidelines WHERE item_code=?", (code,)).fetchone()
            conn.close()
            cls._cache[code] = dict(row) if row else {}
        except Exception:
            cls._cache[code] = {}
        return cls._cache[code]

    @classmethod
    def vuln_kw(cls, code: str) -> list[str]:
        return [k.strip().lower() for k in cls.get(code).get("vuln_keywords", "").split(",") if k.strip()]

    @classmethod
    def ok_kw(cls, code: str) -> list[str]:
        return [k.strip().lower() for k in cls.get(code).get("ok_keywords", "").split(",") if k.strip()]

    @classmethod
    def standard(cls, code: str) -> str:
        g = cls.get(code)
        parts = []
        if g.get("standard"): parts.append(g["standard"])
        if g.get("severity"): parts.append(f"위험도: {g['severity']}")
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
# 구조적 패턴 헬퍼 (유닉스 범용 — 항목 무관)
# ──────────────────────────────────────────────────────────

def _parse_permission(cv: str) -> dict:
    """ls -la 첫 줄에서 rwx 권한 파싱."""
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
    """'N개 발견', 'N found', 'Hidden N:' 등에서 숫자 반환. 없으면 -1."""
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
# 규칙 엔진 (v3 — 비하드코딩, 서비스상태 우선)
# ──────────────────────────────────────────────────────────

def _rule_score(payload: JudgePayload) -> tuple[int, str, bool]:
    """
    (score 0~100, reason, is_conclusive)

    단순화된 규칙 엔진 — 서비스 상태 + 파일/설정 존재 여부만 확인.
    값 내용 분석은 LLM에 위임.

    conclusive 규칙:
      전체 NOT_INSTALLED                    → score=0, conclusive=True
      서비스 체크(비N/A)가 모두 absent      → score=0, conclusive=True

    점수 규칙:
      NOT_INSTALLED  → -25 (스킵)
      NOT_RUNNING    → -10
      RUNNING        → +10
      INSTALLED      → +5
      N/A            → 0
      파일/설정 없음 (서비스 RUNNING/N/A 시) → +15
    """
    checks = payload.check_results

    # ── 전역 확정: 전체 미설치 ───────────────────────────────
    if checks and all(c.service_status.upper() == "NOT_INSTALLED" for c in checks):
        return 0, "전체 서비스/패키지 미설치", True

    # ── 전역 확정: 서비스 체크(비N/A)가 모두 비활성+파일없음 ──
    svc_checks = [c for c in checks if c.service_status.upper() != "N/A"]
    if svc_checks:
        all_absent = all(
            c.service_status.upper() in ("NOT_INSTALLED", "NOT_RUNNING")
            and any(pat in c.collected_value.lower() for pat in _ABSENT_PATTERNS)
            for c in svc_checks
        )
        if all_absent:
            return 0, "관련 서비스 비활성 및 대상 파일 없음", True

        # ── 전역 확정: 서비스 체크가 전부 NOT_RUNNING (미실행) ──
        if all(c.service_status.upper() == "NOT_RUNNING" for c in svc_checks):
            return 0, "관련 서비스 미실행 — 위험 없음", True

    total, reasons = 0, []

    for c in checks:
        cv  = c.collected_value or ""
        svc = c.service_status.upper()
        sub = c.sub_check[:20]

        # ─ 서비스 상태 신호 ──────────────────────────────────
        if svc == "NOT_INSTALLED":
            total -= 25
            reasons.append(f"{sub}:미설치(-25)")
            continue
        elif svc == "NOT_RUNNING":
            total -= 10
            reasons.append(f"{sub}:미실행(-10)")
        elif svc == "RUNNING":
            total += 10
            reasons.append(f"{sub}:실행중(+10)")
        elif svc == "INSTALLED":
            total += 5
            reasons.append(f"{sub}:설치됨(+5)")
        # N/A → 0

        # ─ 파일/설정 없음 (서비스가 있는 경우에만 취약 신호) ──
        if any(pat in cv.lower() for pat in _ABSENT_PATTERNS + ["권한 없음"]):
            if svc not in ("NOT_RUNNING", "NOT_INSTALLED"):
                total += 15
                reasons.append(f"{sub}:파일/설정없음(+15)")
            else:
                reasons.append(f"{sub}:서비스없음→파일없음(무시)")

    total = max(0, min(100, total))
    return total, " | ".join(reasons) or "서비스상태확인", False


# ──────────────────────────────────────────────────────────
# JSON 파싱 (3단계 폴백)
# ──────────────────────────────────────────────────────────

def _strip_thinking(text: str) -> str:
    """gemini-2.5-flash 등 thinking 모델의 <think>…</think> 블록 제거."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"\[THINK\].*?\[/THINK\]", "", text, flags=re.DOTALL | re.IGNORECASE)
    return text.strip()


def _parse_single_json(raw: str) -> dict:
    if not raw or not raw.strip():
        return {}
    cleaned = _strip_thinking(raw)
    cleaned = re.sub(r"```(?:json)?\s*", "", cleaned).strip().rstrip("`").strip()

    # 1) 전체 파싱
    try:
        d = json.loads(cleaned)
        if isinstance(d, list) and d:
            return d[0]
        if isinstance(d, dict):
            return d
    except json.JSONDecodeError:
        pass

    # 2) {} 블록 추출 (가장 큰 블록 우선)
    s, e = cleaned.find("{"), cleaned.rfind("}") + 1
    if s != -1 and e > s:
        try:
            d = json.loads(cleaned[s:e])
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            pass

    # 3) 필드별 정규식 폴백
    result = {}
    for fname, pat in [
        ("vuln_score",  r'"vuln_score"\s*:\s*(\d+)'),
        ("result",      r'"result"\s*:\s*"([^"]+)"'),
        ("reason",      r'"reason"\s*:\s*"((?:[^"\\]|\\.){0,500})"'),
        ("remediation", r'"remediation"\s*:\s*"((?:[^"\\]|\\.){0,300})"'),
    ]:
        m = re.search(pat, cleaned, re.DOTALL)
        if m:
            v = m.group(1)
            result[fname] = int(v) if fname == "vuln_score" else v
    return result


def _parse_batch_json(raw: str, batch: list) -> list:
    if not raw or not raw.strip():
        return [{}] * len(batch)
    cleaned = _strip_thinking(raw)
    cleaned = re.sub(r"```(?:json)?\s*", "", cleaned).strip().rstrip("`").strip()

    # [] 배열 추출
    s, e = cleaned.find("["), cleaned.rfind("]") + 1
    if s != -1 and e > s:
        try:
            data = json.loads(cleaned[s:e])
            if isinstance(data, list):
                while len(data) < len(batch): data.append({})
                return data[:len(batch)]
        except json.JSONDecodeError:
            pass

    # 개별 {} 추출 (nesting 있는 경우 포함)
    results = []
    depth, start = 0, -1
    for i, ch in enumerate(cleaned):
        if ch == "{":
            if depth == 0:
                start = i
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
# LLM 프롬프트
# ──────────────────────────────────────────────────────────

SINGLE_SYSTEM = """주요통신기반시설(주통기) 보안 취약점 점검 전문가.
JSON 객체 하나만 출력. 다른 텍스트 절대 없음.

{"item_code":"U-XX","vuln_score":0~100,"result":"취약|양호|해당없음",
 "reason":"실제 수집값·명령 결과를 직접 인용하며 sub_check별로 4~5줄 상세 분석. 취약 여부 명확히 서술.",
 "remediation":"실행 가능 조치명령 포함, 2줄 이내"}

━━━ 판정 순서 (반드시 이 순서) ━━━
① service_status 확인 (sub_check별)
   · NOT_INSTALLED → 서비스 미설치 → 해당없음 가능
   · NOT_RUNNING   → 서비스 중지 → 취약 위험 낮음, 파일 권한 확인
   · RUNNING/INSTALLED → 설정 확인 필수
   · N/A → 서비스 무관, 파일·설정만 확인

② collected_value 확인
   · "(없음)" 또는 비어있음 → source_command 분석:
     어떤 명령어인지 보고 "왜 결과가 없는지" 추론
     그 다음 raw_output으로 실제 결과 재확인
   · 값이 있으면 → 주통기 판단기준과 직접 비교하며 근거 상세 서술

③ 전체 sub_check 종합 → 취약/양호/해당없음 최종 판정

━━━ reason 작성 규칙 ━━━
· 실제 수집값(예: "-rw-r--r-- 1 root root")을 그대로 인용할 것
· "파일이 없다"는 사실은 이유의 마지막에 간략히 언급
· LLM 분석 내용을 앞에, 규칙 기반 정보는 뒤에 배치

━━━ 점수 기준 ━━━
80+ 명백취약 · 50~79 취약가능 · 20~49 양호가능 · 0~19 명백양호

━━━ reason 작성 ━━━
- 반드시 실제 값 인용
- 주통기 기준과 1:1 비교
- 길이 2~3줄 제한
"""


BATCH_SYSTEM = """주요통신기반시설(주통기) 보안 점검 전문가.
JSON 배열만 출력. 다른 텍스트 없음.

[{"item_code":"U-XX","vuln_score":0~100,"result":"취약|양호|해당없음",
  "reason":"실제 수집값 인용, sub_check별 4~5줄 상세 분석, 취약 여부 명확히",
  "remediation":"2줄 이내"}, ...]

service_status=NOT_INSTALLED/NOT_RUNNING → 해당없음 우선 고려
80+ 명백취약 · 50~79 취약가능 · 20~49 양호가능 · 0~19 명백양호

━━━ reason 작성 ━━━
- 반드시 실제 값 인용
- 주통기 기준과 1:1 비교
- 길이 2~3줄 제한
"""


def _build_single_prompt(payload: JudgePayload, rule_score: int) -> str:
    g_std = _DB.standard(payload.item_code)
    g_cp  = _DB.check_point(payload.item_code)
    g_rem = _DB.remediation(payload.item_code)

    lines = [
        "## 점검 항목",
        f"코드: {payload.item_code}  항목명: {payload.item_name}",
        f"OS: {payload.os_name}  규칙점수: {rule_score}",
        "",
        "## 주통기 기준",
        f"판단기준: {g_std}",
    ]
    if g_cp:
        lines.append(f"점검방법: {g_cp[:300]}")
    if g_rem and g_rem != "수동 확인 필요":
        lines.append(f"조치사항: {g_rem[:200]}")

    lines.append("\n## 수집 데이터")
    for i, c in enumerate(payload.check_results, 1):
        cv = (c.collected_value or "").strip()
        cv_display = (cv or "(없음)")[:300].replace("\n", " ")

        # collected_value가 의미없는 경우에만 raw_output 포함
        cv_meaningful = bool(cv) and cv not in ("(없음)", "N/A", "없음", "-") \
                        and not re.match(r"^(설정\s*없음|파일\s*없음|not\s*found|none|error)", cv, re.I)
        if not cv_meaningful:
            raw_lines = [l for l in (c.raw_output or "").splitlines() if l.strip() and not l.strip().startswith("#")][:8]
            raw_summary = " ↵ ".join(raw_lines)[:500] if raw_lines else None
        else:
            raw_summary = None

        lines.append(f"\n[{i}] {c.sub_check}")
        lines.append(f"  파일/대상: {c.config_file}")
        lines.append(f"  service_status: {c.service_status}")
        lines.append(f"  collected_value: {cv_display}")
        lines.append(f"  source_command: {c.source_command}")
        if raw_summary:
            lines.append(f"  raw_output(폴백): {raw_summary}")

    lines.append("\nJSON 객체 하나만 응답:")
    return "\n".join(lines)


def _best_value(cv: str, raw_output: str, max_len: int = 80) -> str:
    """collected_value가 없으면 raw_output 첫 의미있는 줄로 대체."""
    cv = (cv or "").strip()
    if cv and cv not in ("(없음)", "N/A", "없음", "-"):
        return cv[:max_len].replace("\n", " ")
    for line in (raw_output or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line[:max_len]
    return "(없음)"


def _build_batch_prompt(batch: list, rule_scores: dict) -> str:
    lines = [f"{len(batch)}개 항목 분석:\n"]
    for i, p in enumerate(batch, 1):
        g_std = _DB.standard(p.item_code)
        rs    = rule_scores.get(p.item_code, -1)
        ctx   = [
            f"[{i}] {p.item_code} {p.item_name} | rule={rs} | OS={p.os_name}",
            f"  기준: {g_std[:100]}",
        ]
        for c in p.check_results:
            val = _best_value(c.collected_value, c.raw_output)
            ctx.append(f"  ·{c.sub_check}[{c.service_status}]: {val}")
        lines.append("\n".join(ctx))
    lines.append(f"\n위 {len(batch)}항목 JSON 배열로만 응답:")
    return "\n\n".join(lines)


# ──────────────────────────────────────────────────────────
# Gemini 호출
# ──────────────────────────────────────────────────────────

async def _call_single_item(client, payload: JudgePayload, rule_score: int, label: str) -> dict:
    prompt = _build_single_prompt(payload, rule_score)
    await _rate_limit_wait(estimated_tokens=4000)
    
    for attempt in range(1, GEMINI_MAX_RETRY + 1):
        try:
            resp = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SINGLE_SYSTEM,
                    temperature=0.1,
                    max_output_tokens=600,
                    thinking_config=types.ThinkingConfig(thinkingBudget=4096),
                ),
            )
            raw = (resp.text or "") if hasattr(resp, "text") else ""

            if not raw.strip():
                try:
                    finish = resp.candidates[0].finish_reason if resp.candidates else "UNKNOWN"
                except Exception:
                    finish = "UNKNOWN"
                print(f"    [경고] {payload.item_code} 빈응답 finish_reason={finish} → 재시도")
                await asyncio.sleep(GEMINI_REQUEST_DELAY)
                continue

            if not raw.strip().startswith(("{", "[", "`")):
                print(f"    [경고] {payload.item_code} 비JSON: {raw[:80]!r}")

            parsed = _parse_single_json(raw)
            if parsed:
                return parsed

            print(f"    [경고] {payload.item_code} 파싱실패(시도{attempt}): {raw[:80]!r}")
            await asyncio.sleep(GEMINI_REQUEST_DELAY)

        except Exception as e:
            err = str(e)
            if "429" in err or "RESOURCE_EXHAUSTED" in err or "Too Many Requests" in err:
                wait = min(120, GEMINI_RETRY_DELAY * (2 ** (attempt - 1)))
                print(f"    [429] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
                await asyncio.sleep(wait)
            else:
                print(f"    [오류] {label}: {err}")
                return {}

    print(f"    [실패] {label} 재시도 초과")
    return {}

# 분당 사용량 추적 (모듈 레벨 전역 변수)
_rpm_window: list = []   # 요청 시각 목록
_tpm_used:   int  = 0    # 현재 분 토큰 사용량
_tpm_reset:  float = 0.0 # 현재 분 시작 시각

async def _rate_limit_wait(estimated_tokens: int = 3000):
    """RPM/TPM 한도 초과 예상 시 다음 분까지 대기."""
    import time
    global _rpm_window, _tpm_used, _tpm_reset

    now = time.time()

    # 60초 지난 요청 제거
    _rpm_window = [t for t in _rpm_window if now - t < 60]

    # 분 초기화
    if now - _tpm_reset >= 60:
        _tpm_used  = 0
        _tpm_reset = now

    # RPM 한도 체크
    if len(_rpm_window) >= MAX_RPM:
        oldest = _rpm_window[0]
        wait = 61 - (now - oldest)
        if wait > 0:
            print(f"    [rate limit] RPM {len(_rpm_window)}/{MAX_RPM} → {wait:.0f}초 대기")
            await asyncio.sleep(wait)
            now = time.time()
            _rpm_window = [t for t in _rpm_window if now - t < 60]

    # TPM 한도 체크
    if _tpm_used + estimated_tokens > MAX_TPM:
        wait = 61 - (now - _tpm_reset)
        if wait > 0:
            print(f"    [rate limit] TPM {_tpm_used}/{MAX_TPM} → {wait:.0f}초 대기")
            await asyncio.sleep(wait)
            _tpm_used  = 0
            _tpm_reset = time.time()

    # 사용량 기록
    _rpm_window.append(time.time())
    _tpm_used += estimated_tokens

async def _call_batch(client, batch: list, rule_scores: dict, label: str) -> list:
    prompt = _build_batch_prompt(batch, rule_scores)
    await _rate_limit_wait(estimated_tokens=500 * len(batch) + 2000)
    
    for attempt in range(1, GEMINI_MAX_RETRY + 1):
        try:
            resp = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=BATCH_SYSTEM,
                    temperature=0.1,
                    max_output_tokens=280 * len(batch),
                    thinking_config=types.ThinkingConfig(thinkingBudget=0),
                ),
            )
            raw = (resp.text or "") if hasattr(resp, "text") else ""
            if not raw.strip():
                print(f"    [경고] 배치 빈응답 → 재시도")
                await asyncio.sleep(GEMINI_REQUEST_DELAY)
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

def _finalize(payload: JudgePayload, rule_score: int, rule_reason: str,
              llm_data: dict, mode: str) -> JudgeResult:
    code      = payload.item_code
    llm_score = int(llm_data.get("vuln_score", 50)) if llm_data else -1

    # ─ 점수 및 근거 계산 ────────────────────────────────────
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
            final_score = round(rule_score * SCORE_WEIGHT_RULE + llm_score * SCORE_WEIGHT_LLM)
            note        = f"(규칙{rule_score}×0.6+LLM{llm_score}×0.4={final_score})"
            reason      = f"[LLM] {llm_data.get('reason', '')} | [규칙보조] {rule_reason} | {note}"
            remediation = llm_data.get("remediation", "수동 확인 필요")

    # ─ LLM 해당없음 명시 시 우선 적용 ──────────────────────
    if llm_data and llm_data.get("result") == "해당없음":
        llm_reason = llm_data.get("reason", "서비스 없음 또는 해당 없음")
        try:
            collected_json = json.dumps(
                [{"sub_check": c.sub_check, "config_file": c.config_file,
                  "collected_value": c.collected_value, "service_status": c.service_status,
                  "source_command": c.source_command}
                 for c in payload.check_results],
                ensure_ascii=False
            )
        except Exception:
            collected_json = "[]"
        return JudgeResult(
            scan_id=payload.scan_id, item_code=code,
            item_name=payload.item_name,
            guideline_ref=f"주통기 Unix 서버 {code}",
            result="해당없음",
            reason=f"[LLM] {llm_reason}",
            remediation="해당 없음", confidence=0.9,
            os_name=getattr(payload, "os_name", ""),
            category=_DB.category(code) or getattr(payload, "category", ""),
            severity=_DB.severity(code),
            judge_mode=mode,
            collected_json=collected_json,
        )

    # ─ 최종 결과 결정 ───────────────────────────────────────
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

    reason = " | ".join(reason.split(" | ")[:5])

    # ─ collected_json 직렬화 ────────────────────────────────
    try:
        collected_json = json.dumps(
            [{"sub_check": c.sub_check, "config_file": c.config_file,
              "collected_value": c.collected_value, "service_status": c.service_status,
              "source_command": c.source_command}
             for c in payload.check_results],
            ensure_ascii=False
        )
    except Exception:
        collected_json = "[]"

    return JudgeResult(
        scan_id=payload.scan_id, item_code=code,
        item_name=payload.item_name,
        guideline_ref=f"주통기 Unix 서버 {code}",
        result=result, reason=reason,
        remediation=remediation, confidence=conf,
        os_name=getattr(payload, "os_name", ""),
        category=_DB.category(code) or getattr(payload, "category", ""),
        severity=_DB.severity(code),
        judge_mode=mode,
        collected_json=collected_json,
    )


# ──────────────────────────────────────────────────────────
# BatchJudge — 공개 API
# ──────────────────────────────────────────────────────────

class BatchJudge:
    """
    사용법:
        results = asyncio.run(BatchJudge.run(payloads, mode="hybrid"))

    judge_mode:
        "hybrid"    규칙×0.6 + LLM×0.4  (기본)
        "rule_only" LLM 없음 (논문 실험/빠른 테스트)
        "llm_only"  규칙 무시 (논문 실험용)
    """

    @staticmethod
    async def run(
        payloads: list,
        api_key: Optional[str] = None,
        mode: str = "hybrid",
    ) -> list:
        if api_key is None:
            api_key = _get_api_key()

        # ── 1단계: 규칙 평가 및 분류 ──
        # 단순화: 규칙 확정(NOT_INSTALLED 등) → 즉시 처리
        #         나머지 전부 → 배치 LLM (개별 LLM 제거 → API 호출 수 최소화)
        certain:  list = []   # 규칙 확정 (취약/해당없음)
        need_llm: list = []   # LLM 판정 필요 → 배치 처리
        rule_map: dict = {}

        for p in payloads:
            score, reason, conclusive = _rule_score(p)
            rule_map[p.item_code] = (score, reason)

            if mode == "rule_only":
                certain.append((p, score, reason))
            elif conclusive:   # 취약 확정(≥RULE_CERTAIN_VULN)이든 양호 확정(낮은 점수)이든 LLM 스킵
                certain.append((p, score, reason))
            else:
                need_llm.append(p)

        n_batches = (len(need_llm) + BATCH_SIZE - 1) // BATCH_SIZE if need_llm else 0
        eta = n_batches * (GEMINI_REQUEST_DELAY + 5)

        print(
            f"[BatchJudge] mode={mode} | model={GEMINI_MODEL}\n"
            f"  전체={len(payloads)} | 규칙확정={len(certain)} | "
            f"배치LLM={len(need_llm)}({n_batches}배치)\n"
            f"  예상≈{eta:.0f}초({eta/60:.1f}분)"
        )

        # ── 2단계: 규칙 확정 즉시 처리 ──
        results: list = []
        for p, score, reason in certain:
            r = _finalize(p, score, reason, {}, mode)
            results.append(r)
            print(f"  [규칙확정] {p.item_code}({score}점) → {r.result}")

        if not need_llm or not api_key:
            if not api_key and need_llm:
                print("[BatchJudge] API KEY 없음 → 규칙 점수로 대체")
            for p in need_llm:
                score, reason = rule_map[p.item_code]
                results.append(_finalize(p, score, reason, {}, "rule_only"))
            _print_summary(results)
            return results

        client = genai.Client(api_key=api_key)
        rule_scores_map = {c: s for c, (s, _) in rule_map.items()}

        # ── 3단계: 전체 배치 LLM ──
        print(f"\n[배치LLM] {len(need_llm)}건 ({n_batches}배치)...")
        for bi, bs in enumerate(range(0, len(need_llm), BATCH_SIZE)):
            batch = need_llm[bs:bs + BATCH_SIZE]
            codes = ",".join(p.item_code for p in batch)
            label = f"배치{bi+1}/{n_batches}[{codes}]"
            print(f"  {label}")
            batch_out = await _call_batch(client, batch, rule_scores_map, label)
            for p, llm_d in zip(batch, batch_out):
                score, reason = rule_map[p.item_code]
                r = _finalize(p, score, reason, llm_d or {}, mode)
                results.append(r)
                print(f"    {p.item_code}: 규칙={score} LLM={(llm_d or {}).get('vuln_score','N/A')} → {r.result}({r.confidence:.0%})")
            if bs + BATCH_SIZE < len(need_llm):
                await asyncio.sleep(GEMINI_REQUEST_DELAY)

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
