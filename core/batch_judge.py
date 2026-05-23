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
GEMINI_REQUEST_DELAY = float(os.getenv("GEMINI_REQUEST_DELAY", "6"))
GEMINI_RETRY_DELAY   = float(os.getenv("GEMINI_RETRY_DELAY", "70"))
GEMINI_MAX_RETRY     = int(os.getenv("GEMINI_MAX_RETRY", "5"))
BATCH_SIZE           = int(os.getenv("BATCH_SIZE", "10"))
RULE_CERTAIN_VULN    = int(os.getenv("RULE_CERTAIN_VULN", "85"))
GUIDELINE_DB_PATH    = os.getenv("GUIDELINE_DB_PATH", "./db/guidelines.db")

SCORE_WEIGHT_RULE = 0.6
SCORE_WEIGHT_LLM  = 0.4
THRESHOLD_VULN    = 70
THRESHOLD_OK      = 40


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

    서비스 상태 우선 원칙:
      NOT_INSTALLED  → -25 / sub_check 스킵  (서비스 없음)
      NOT_RUNNING    → -15  (설치됨, 중지)
      INSTALLED      → +5   (파일 존재, 가동 불명)
      RUNNING        → +10  (실행 중, 설정 확인 필수)
      N/A            → 0    (순수 파일/설정 체크)

    설정값 분석 원칙:
      파일/설정 없음 → 서비스 없을 때 무시, 아닐 때 +15
      ls -la 권한   → world_write(+50) group_write(+30) world_read(+20) 양호(-10)
      N개 발견 패턴 → 0개(-20) 1~5개(+20) 6+개(+35)
      shadow:x: 패턴 → -20 (shadow 사용 중 = 양호)
      DB vuln_keywords → +40 / ok_keywords → -30

    conclusive 규칙:
      전체 NOT_INSTALLED         → score=0, conclusive=True
      서비스체크 전체 absent     → score=0, conclusive=True
    """
    checks = payload.check_results
    code   = payload.item_code
    vkws   = _DB.vuln_kw(code)
    okws   = _DB.ok_kw(code)

    # ── 전역 확정: 전체 미설치 ──────────────────────────────
    if checks and all(c.service_status.upper() == "NOT_INSTALLED" for c in checks):
        return 0, "전체 서비스/패키지 미설치", True

    # ── 전역 확정: 서비스 체크(비N/A)가 모두 absent ─────────
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
        sub  = c.sub_check[:20]

        # ─ Step 1: 서비스 상태 신호 ──────────────────────────
        if svc == "NOT_INSTALLED":
            total -= 25
            reasons.append(f"{sub}:미설치(-25)")
            continue   # 설치 안 됨 → 이 항목 설정 확인 불필요

        if svc == "NOT_RUNNING":
            total -= 15
            reasons.append(f"{sub}:미실행(-15)")
            # 파일 권한 등은 계속 확인 (설치됨이므로)

        elif svc == "RUNNING":
            total += 10
            reasons.append(f"{sub}:실행중(+10)")

        elif svc == "INSTALLED":
            total += 5
            reasons.append(f"{sub}:설치됨(+5)")

        # N/A → 0 (서비스 신호 없음, 파일/설정 확인으로)

        # ─ Step 2: 파일/설정 없음 처리 ─────────────────────────
        if any(pat in comb for pat in _ABSENT_PATTERNS + ["권한 없음"]):
            if svc in ("NOT_RUNNING", "NOT_INSTALLED"):
                reasons.append(f"{sub}:서비스없음→파일없음(무시)")
            elif "권한 없음" in comb:
                total += 15
                reasons.append(f"{sub}:읽기권한없음(+15)")
            else:
                total += 15
                reasons.append(f"{sub}:파일/설정없음(+15)")
            continue

        # ─ Step 3: ls -la 권한 파싱 (유닉스 범용) ──────────────
        perm = _parse_permission(cv)
        if perm:
            if perm.get("world_write"):
                total += 50; reasons.append(f"{sub}:world_write(+50)")
            elif perm.get("group_write"):
                total += 30; reasons.append(f"{sub}:group_write(+30)")
            elif perm.get("world_read"):
                total += 20; reasons.append(f"{sub}:world_read(+20)")
            else:
                total -= 10; reasons.append(f"{sub}:권한양호(-10)")
            if not re.search(r'\broot\b', cv):
                total += 20; reasons.append(f"{sub}:비root소유(+20)")
            continue

        # ─ Step 4: "N개 발견" 패턴 (유닉스 범용) ──────────────
        found_n = _count_found(cv)
        if found_n >= 0:
            if found_n == 0:
                total -= 20; reasons.append(f"{sub}:발견없음(-20)")
            elif found_n <= 5:
                total += 20; reasons.append(f"{sub}:{found_n}개발견(+20)")
            else:
                total += 35; reasons.append(f"{sub}:{found_n}개발견(+35)")
            continue

        # ─ Step 5: shadow 패스워드 패턴 (유닉스 범용) ───────────
        if re.search(r'[a-z_][a-z0-9_-]*:x:\d+:\d+:', comb):
            total -= 20; reasons.append(f"{sub}:shadow패스워드(-20)")
            continue

        # ─ Step 6: RUNNING인데 안전 설정 없음 ─────────────────
        if svc == "RUNNING":
            if not any(k in comb for k in _SAFE_CONFIG_WORDS):
                total += 20; reasons.append(f"{sub}:실행+제한없음(+20)")

        # ─ Step 7: DB 키워드 매칭 (비하드코딩) ─────────────────
        matched = False
        for kw in vkws:
            if kw in comb:
                total += 40; reasons.append(f"{sub}:취약kw[{kw[:10]}](+40)")
                matched = True; break
        if not matched:
            for kw in okws:
                if kw in comb:
                    total -= 30; reasons.append(f"{sub}:양호kw[{kw[:10]}](-30)")
                    break

    total = max(0, min(100, total))
    return total, " | ".join(reasons) or "규칙매칭없음", False


# ──────────────────────────────────────────────────────────
# JSON 파싱 (3단계 폴백)
# ──────────────────────────────────────────────────────────

def _parse_single_json(raw: str) -> dict:
    if not raw or not raw.strip():
        return {}
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()

    # 1) 전체 파싱
    try:
        d = json.loads(cleaned)
        if isinstance(d, list) and d:
            return d[0]
        if isinstance(d, dict):
            return d
    except json.JSONDecodeError:
        pass

    # 2) {} 블록 추출
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
    for m in re.finditer(r'\{[^{}]+\}', cleaned, re.DOTALL):
        try:
            obj = json.loads(m.group())
            if "item_code" in obj or "vuln_score" in obj:
                results.append(obj)
        except json.JSONDecodeError:
            pass
    while len(results) < len(batch): results.append({})
    return results[:len(batch)]


# ──────────────────────────────────────────────────────────
# LLM 프롬프트
# ──────────────────────────────────────────────────────────

SINGLE_SYSTEM = """주요통신기반시설(주통기) 보안 취약점 점검 전문가.
JSON 객체 하나만 출력. 다른 텍스트 절대 없음.

{"item_code":"U-XX","vuln_score":0~100,"result":"취약|양호|해당없음",
 "reason":"sub_check별 판정 근거 (실제 설정값·명령 결과 인용), 5줄 이내",
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
   · 값이 있으면 → 주통기 판단기준과 직접 비교

③ 전체 sub_check 종합 → 취약/양호/해당없음 최종 판정

━━━ 점수 기준 ━━━
80+ 명백취약 · 50~79 취약가능 · 20~49 양호가능 · 0~19 명백양호"""


BATCH_SYSTEM = """주요통신기반시설(주통기) 보안 점검 전문가.
JSON 배열만 출력. 다른 텍스트 없음.

[{"item_code":"U-XX","vuln_score":0~100,"result":"취약|양호|해당없음",
  "reason":"5줄 이내","remediation":"2줄 이내"}, ...]

service_status=NOT_INSTALLED/NOT_RUNNING → 해당없음 우선 고려
80+ 명백취약 · 50~79 취약가능 · 20~49 양호가능 · 0~19 명백양호"""


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
        cv = (c.collected_value or "(없음)")[:300].replace("\n", " ")
        raw_lines = [l for l in (c.raw_output or "").splitlines() if l.strip()][:5]
        raw_summary = " ↵ ".join(raw_lines) if raw_lines else "(없음)"

        lines.append(f"\n[{i}] {c.sub_check}")
        lines.append(f"  파일/대상: {c.config_file}")
        lines.append(f"  service_status: {c.service_status}")
        lines.append(f"  collected_value: {cv}")
        lines.append(f"  source_command: {c.source_command}")
        lines.append(f"  raw_output(앞5줄): {raw_summary}")

    lines.append("\nJSON 객체 하나만 응답:")
    return "\n".join(lines)


def _build_batch_prompt(batch: list, rule_scores: dict) -> str:
    lines = [f"{len(batch)}개 항목 분석:\n"]
    for i, p in enumerate(batch, 1):
        g_std = _DB.standard(p.item_code)
        g_cp  = _DB.check_point(p.item_code)
        rs    = rule_scores.get(p.item_code, -1)
        ctx   = [
            f"[{i}] {p.item_code} {p.item_name} | rule_score={rs} | OS={p.os_name}",
            f"  기준: {g_std[:120]}",
        ]
        if g_cp:
            ctx.append(f"  점검방법: {g_cp[:80]}")
        for c in p.check_results:
            cv = (c.collected_value or "(없음)")[:100].replace("\n", " ")
            ctx.append(f"  ·{c.sub_check}: {cv} [svc:{c.service_status}]")
        lines.append("\n".join(ctx))
    lines.append(f"\n위 {len(batch)}항목 JSON 배열로만 응답:")
    return "\n\n".join(lines)


# ──────────────────────────────────────────────────────────
# Gemini 호출
# ──────────────────────────────────────────────────────────

async def _call_single_item(client, payload: JudgePayload, rule_score: int, label: str) -> dict:
    prompt = _build_single_prompt(payload, rule_score)

    for attempt in range(1, GEMINI_MAX_RETRY + 1):
        try:
            resp = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SINGLE_SYSTEM,
                    temperature=0.1,
                    max_output_tokens=700,
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
                wait = GEMINI_RETRY_DELAY * attempt
                print(f"    [429] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
                await asyncio.sleep(wait)
            else:
                print(f"    [오류] {label}: {err}")
                return {}

    print(f"    [실패] {label} 재시도 초과")
    return {}


async def _call_batch(client, batch: list, rule_scores: dict, label: str) -> list:
    prompt = _build_batch_prompt(batch, rule_scores)

    for attempt in range(1, GEMINI_MAX_RETRY + 1):
        try:
            resp = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=BATCH_SYSTEM,
                    temperature=0.1,
                    max_output_tokens=900 * len(batch),
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
                wait = GEMINI_RETRY_DELAY * attempt
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
            reason      = f"[규칙] {rule_reason} | [LLM] {llm_data.get('reason', '')} | {note}"
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
        certain:         list = []   # 규칙 확정 취약
        confirmed_ok:    list = []   # 규칙 확정 양호 → 배치 LLM
        need_individual: list = []   # 불확실/취약 → 개별 LLM
        rule_map:        dict = {}

        for p in payloads:
            score, reason, conclusive = _rule_score(p)
            rule_map[p.item_code] = (score, reason)

            if mode == "rule_only":
                certain.append((p, score, reason))
            elif conclusive and score >= RULE_CERTAIN_VULN:
                certain.append((p, score, reason))
            elif conclusive and score < THRESHOLD_VULN:
                confirmed_ok.append(p)
            else:
                need_individual.append(p)

        n_ok_batches = (len(confirmed_ok) + BATCH_SIZE - 1) // BATCH_SIZE if confirmed_ok else 0
        eta = (n_ok_batches + len(need_individual)) * (GEMINI_REQUEST_DELAY + 5)

        print(
            f"[BatchJudge] mode={mode} | model={GEMINI_MODEL}\n"
            f"  전체={len(payloads)} | 규칙확정취약={len(certain)} | "
            f"확정양호(배치LLM)={len(confirmed_ok)}({n_ok_batches}배치) | "
            f"개별LLM={len(need_individual)}\n"
            f"  예상≈{eta:.0f}초({eta/60:.1f}분)"
        )

        # ── 2단계: 규칙 확정 취약 즉시 처리 ──
        results: list = []
        for p, score, reason in certain:
            r = _finalize(p, score, reason, {}, mode)
            results.append(r)
            print(f"  [확정취약] {p.item_code}({score}점) → {r.result}")

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

        # ── 3단계: 확정 양호 → 순차 배치 LLM ──
        if confirmed_ok:
            print(f"\n[배치LLM] 확정양호 {len(confirmed_ok)}건...")
            for bi, bs in enumerate(range(0, len(confirmed_ok), BATCH_SIZE)):
                batch = confirmed_ok[bs:bs + BATCH_SIZE]
                codes = ",".join(p.item_code for p in batch)
                label = f"양호배치{bi+1}[{codes}]"
                print(f"  {label}")
                batch_out = await _call_batch(client, batch, rule_scores_map, label)
                for p, llm_d in zip(batch, batch_out):
                    score, reason = rule_map[p.item_code]
                    r = _finalize(p, score, reason, llm_d or {}, mode)
                    results.append(r)
                    print(f"    {p.item_code}: 규칙={score} LLM={(llm_d or {}).get('vuln_score','N/A')} → {r.result}({r.confidence:.0%})")
                if bs + BATCH_SIZE < len(confirmed_ok):
                    await asyncio.sleep(GEMINI_REQUEST_DELAY)

        # ── 4단계: 불확실/취약 → 개별 LLM ──
        if need_individual:
            print(f"\n[개별LLM] {len(need_individual)}건 순차 처리...")
            for idx, p in enumerate(need_individual, 1):
                score, reason = rule_map[p.item_code]
                label = f"개별{idx}/{len(need_individual)}[{p.item_code}]"
                print(f"  [LLM] {label} (규칙={score})")
                llm_d = await _call_single_item(client, p, score, label)
                r = _finalize(p, score, reason, llm_d, mode)
                results.append(r)
                print(f"    → 규칙={score} LLM={(llm_d or {}).get('vuln_score','N/A')} 최종={r.result}({r.confidence:.0%})")
                if idx < len(need_individual):
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
