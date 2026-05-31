"""
batch_judge.py  (v10)
---------------------
규칙/LLM 하이브리드 판정 엔진.

변경사항 (v10):
  1. 규칙 엔진 우선순위 재설계: 스크립트 직접 판정 → 서비스 상태 → 패턴 매칭
  2. script_result(양호/취약/규칙불가) 를 models.py에서 받아 최우선 신호로 사용
  3. LLM 역할 분리: 취약/양호 확정 항목은 reason/remediation 생성에만 사용
  4. 규칙불가 항목: LLM이 전권 판정
  5. 점수 혼합(0.3/0.7) 제거 — 스크립트 판정 결과 뒤집기 불가 (할루시네이션 차단)
  6. reason/remediation: 5문장, 사용자 친화적, 점수 표기 없음

흐름:
  1단계 규칙 엔진 → 6개 버킷 분류
    ├─ NOT_INSTALLED                    → 즉시 해당없음 (LLM 없음)
    ├─ 서비스 전체 비활성(NOT_RUNNING) → 즉시 양호 (LLM 없음)
    ├─ script=취약 (확정)              → LLM: reason/remediation 생성 (결과 고정=취약)
    ├─ script=양호 (확정)              → LLM: reason/remediation 생성 (결과 고정=양호)
    ├─ script=규칙불가                 → LLM: 전권 판정
    └─ 패턴매칭 불확실                 → LLM: 전권 판정

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

# gemini-2.5-flash — AI Studio 유료(pay-as-you-go): 1000 RPM / 4M TPM
# thinking_budget=0 필수: 기본 활성 시 출력 비용 15× 증가 ($0.60 → $3.50/1M)
GEMINI_MODEL_DEFAULT = "gemini-2.5-flash"


def _gemini_model() -> str:
    return os.getenv("GEMINI_MODEL", GEMINI_MODEL_DEFAULT)

# 429 후 첫 대기(초) — 지수 백오프: 30 → 60 → 120
GEMINI_RETRY_DELAY = float(os.getenv("GEMINI_RETRY_DELAY", "30.0"))
GEMINI_MAX_RETRY   = int(os.getenv("GEMINI_MAX_RETRY",   "3"))
RULE_CERTAIN_VULN  = int(os.getenv("RULE_CERTAIN_VULN",  "85"))
GUIDELINE_DB_PATH  = os.getenv("GUIDELINE_DB_PATH",   "./db/guidelines.db")

# LLM 호출은 순차(1) 고정 — 이벤트루프 충돌 방지
MAX_CONCURRENT     = 1

# 프롬프트 총 글자수 상한
MAX_PROMPT_CHARS   = int(os.getenv("MAX_PROMPT_CHARS", "4000"))

# RPM / TPM 상한 (Rate Limiter)
# 유료 AI Studio 1000 RPM / 4M TPM 기준
# REQUEST_MIN_DELAY=3 → 20 RPM, 여유율 98%
# 72항목 × 3초 ≈ 3.6분, 예상 비용 ≈ 23 KRW
MAX_RPM            = int(os.getenv("MAX_RPM",   "20"))
MAX_TPM            = int(os.getenv("MAX_TPM",   "2000000"))
REQUEST_MIN_DELAY  = float(os.getenv("REQUEST_MIN_DELAY", "3.0"))
PROMPT_DUMP_FILE   = os.getenv("PROMPT_DUMP_FILE", "/tmp/syeon_prompts_latest.txt")

SCORE_WEIGHT_RULE  = 0.30
SCORE_WEIGHT_LLM   = 0.70
THRESHOLD_VULN     = 70
THRESHOLD_OK       = 40


def _get_api_key() -> str:
    return os.getenv("GEMINI_API_KEY") or ""


# ──────────────────────────────────────────────────────────
# Rate Limiter (모듈 레벨 — 순차 처리이므로 Lock 불필요)
# ──────────────────────────────────────────────────────────

_rl_window:    list  = []
_rl_tpm_used:  int   = 0
_rl_tpm_reset: float = 0.0


def _reset_rl_window():
    """429 복구 후 rate limiter 윈도우 초기화 — 재개 시 버스트 방지."""
    global _rl_window, _rl_tpm_used, _rl_tpm_reset
    _rl_window    = []
    _rl_tpm_used  = 0
    _rl_tpm_reset = _time.time()


async def _rate_limit_wait(estimated_tokens: int = 2000):
    """RPM / TPM 한도 초과 예상 시 다음 분까지 대기.
    MAX_CONCURRENT=1 순차 처리이므로 Lock 없이 직접 실행.
    """
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

    # 항목 간 최소 딜레이 (RPM 안전 간격)
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

def _get_script_result(checks) -> str:
    """check_results 의 script_result 들을 보수적으로 집계.

    이전: 첫 번째 비어있지 않은 값 반환 → 다중 sub_check 항목에서 뒤쪽 '취약' 누락.
    현재: 보수적 집계
       - 하나라도 '취약'   → '취약' (확정 위반이 존재)
       - 모두 '양호'       → '양호'
       - 그 외             → '규칙불가' (LLM 에 위임)
    """
    signals = [(getattr(c, "script_result", "") or "").strip() for c in checks]
    signals = [s for s in signals if s]  # 빈 값 제외
    if not signals:
        return ""
    if any(s == "취약" for s in signals):
        return "취약"
    if all(s == "양호" for s in signals):
        return "양호"
    return "규칙불가"


def _rule_score(payload: JudgePayload) -> tuple[int, str, bool, str]:
    """
    반환: (score 0~100, reason, is_conclusive, script_result)
    score == -1 → 전체 미설치 (해당없음 마커)

    우선순위:
      P1. script_result == 규칙불가  → (50, ..., False, "규칙불가")  — LLM 전권
      P2. 전체 NOT_INSTALLED         → (-1, ..., True,  ...)          — 해당없음 즉시
      P3. 서비스 전체 비활성         → (0,  ..., True,  ...)          — 양호 즉시
      P4. script_result == 취약      → (90, ..., True,  "취약")       — LLM text only
      P5. script_result == 양호      → (10, ..., True,  "양호")       — LLM text only
      P6. 패턴 매칭                  → (계산값, ..., False, ...)       — LLM hybrid
    """
    checks = payload.check_results
    code   = payload.item_code
    vkws   = _DB.vuln_kw(code)
    okws   = _DB.ok_kw(code)

    script_result = _get_script_result(checks)

    # P1: 규칙불가 → LLM 전권
    if script_result == "규칙불가":
        return 50, "스크립트 자동 판정 불가 — LLM 판정 필요", False, script_result

    # P2: 전체 NOT_INSTALLED → 해당없음
    if checks and all(c.service_status.upper() == "NOT_INSTALLED" for c in checks):
        return -1, "전체 서비스/패키지 미설치", True, script_result

    # P3: 서비스 점검 항목 전체 비활성 → 양호 (서비스 없으면 위협 없음)
    svc_checks = [c for c in checks if c.service_status.upper() != "N/A"]
    if svc_checks and all(
        c.service_status.upper() in ("NOT_INSTALLED", "NOT_RUNNING")
        for c in svc_checks
    ):
        return 0, "관련 서비스 전체 비활성 — 현재 위협 없음", True, script_result

    # P4: 스크립트 직접 판정 취약 → 결과 고정 (score=90, conclusive)
    if script_result == "취약":
        return 90, "점검 스크립트 직접 판정: 취약", True, script_result

    # P5: 스크립트 직접 판정 양호 → 결과 고정 (score=10, conclusive)
    if script_result == "양호":
        return 10, "점검 스크립트 직접 판정: 양호", True, script_result

    # P6: 패턴 매칭 (스크립트 결과 없거나 불명확할 때)
    total, reasons = 0, []

    for c in checks:
        cv   = c.collected_value or ""
        comb = cv.lower()
        svc  = c.service_status.upper()
        sub  = c.sub_check[:18]

        # 서비스 상태
        if svc == "NOT_INSTALLED":
            total -= 25; reasons.append(f"{sub}:미설치"); continue
        if svc == "NOT_RUNNING":
            total -= 25; reasons.append(f"{sub}:비실행"); continue
        elif svc == "RUNNING":
            total += 15; reasons.append(f"{sub}:실행중")
        elif svc == "INSTALLED":
            total += 5;  reasons.append(f"{sub}:설치됨")

        # 파일/설정 없음
        if any(pat in comb for pat in _ABSENT_PATTERNS + ["권한 없음"]):
            total += 12; reasons.append(f"{sub}:파일없음"); continue

        # nouser/nogroup (소유자 미설정 파일)
        if re.search(r'\bnouser\b|\bnogroup\b', comb):
            total += 15; reasons.append(f"{sub}:nouser/nogroup")

        # 파일 권한 패턴 (ls -la)
        perm = _parse_permission(cv)
        if perm:
            if perm.get("world_write"):
                total += 25; reasons.append(f"{sub}:world_write")
            elif perm.get("group_write"):
                total += 12; reasons.append(f"{sub}:group_write")
            elif perm.get("world_read"):
                total += 10; reasons.append(f"{sub}:world_read")
            else:
                total -= 10; reasons.append(f"{sub}:권한양호")
            if not re.search(r'\broot\b', cv):
                total += 15; reasons.append(f"{sub}:비root소유")
            continue

        # N개 발견 패턴
        found_n = _count_found(cv)
        if found_n >= 0:
            if found_n == 0:
                total -= 20; reasons.append(f"{sub}:발견없음")
            elif found_n <= 5:
                total += 20; reasons.append(f"{sub}:{found_n}개발견")
            else:
                total += 35; reasons.append(f"{sub}:{found_n}개발견")
            continue

        # shadow 패스워드 (x: → 안전)
        if re.search(r'[a-z_][a-z0-9_-]*:x:\d+:\d+:', comb):
            total -= 20; reasons.append(f"{sub}:shadow패스워드"); continue

        # RUNNING인데 안전 설정 키워드 없음
        if svc == "RUNNING" and not any(k in comb for k in _SAFE_CONFIG_WORDS):
            total += 20; reasons.append(f"{sub}:실행+제한없음")

        # 가이드라인 DB 키워드
        matched = False
        for kw in vkws:
            if kw in comb:
                total += 40; reasons.append(f"{sub}:취약kw[{kw[:8]}]")
                matched = True; break
        if not matched:
            for kw in okws:
                if kw in comb:
                    total -= 30; reasons.append(f"{sub}:양호kw[{kw[:8]}]")
                    break

    total = max(0, min(100, total))
    return total, " | ".join(reasons) or "패턴매칭없음", False, script_result


# ──────────────────────────────────────────────────────────
# 프롬프트 빌더 (간결 버전 + 글자수 상한)
# ──────────────────────────────────────────────────────────

def _truncate(text: str, limit: int) -> str:
    return text[:limit] + "…" if len(text) > limit else text


def _build_single_prompt(payload: JudgePayload, rule_score: int, script_result: str = "") -> str:
    code    = payload.item_code
    g_std   = _DB.standard(code)
    g_cp    = _DB.check_point(code)

    os_name = payload.os_name or ""
    if any(k in os_name.lower() for k in ("debian", "ubuntu")):
        os_hint = "Debian/Ubuntu"
    elif any(k in os_name.lower() for k in ("rhel", "centos", "rocky", "alma")):
        os_hint = "RHEL 계열"
    else:
        os_hint = os_name or "Linux"

    # 서비스 상태 요약 (판정 최우선 정보)
    svc_parts = []
    for c in payload.check_results:
        svc_parts.append(f"{c.sub_check[:20]}={c.service_status}")
    svc_summary = " / ".join(svc_parts) if svc_parts else "N/A"

    lines = [
        f"[점검항목] {code}: {payload.item_name}",
        f"[OS] {os_hint}",
        f"[서비스상태] {svc_summary}  ← 판정 최우선 기준",
        f"[주통기기준] {_truncate(g_std, 300)}",
    ]
    if g_cp:
        lines.append(f"[점검포인트] {_truncate(g_cp, 200)}")

    # 스크립트 직접 판정 결과 전달 — LLM이 결과를 뒤집지 않도록
    if script_result == "취약":
        lines.append(f"[스크립트판정] 취약 ← 이미 확정된 결과. result 필드는 반드시 '취약'으로 출력하고 reason/remediation 위주로 상세 작성")
    elif script_result == "양호":
        lines.append(f"[스크립트판정] 양호 ← 이미 확정된 결과. result 필드는 반드시 '양호'으로 출력하고 reason/remediation 위주로 상세 작성")
    elif script_result == "규칙불가":
        lines.append(f"[스크립트판정] 규칙불가 ← 자동 판정 불가. 수집값 분석 후 직접 판정 필요")

    lines.append("")
    lines.append("[수집결과] ← 아래 값만 근거로 판정할 것")
    for i, c in enumerate(payload.check_results, 1):
        cv = _truncate((c.collected_value or "(없음)").replace("\n", " "), 600)
        lines.append(f"  ({i}) {c.sub_check[:40]}")
        lines.append(f"      service_status: {c.service_status}")
        lines.append(f"      collected_value: {cv}")

    lines.append("")
    lines.append("※ 수집결과에 없는 내용 추가 금지. JSON만 출력.")

    full = "\n".join(lines)
    if len(full) > MAX_PROMPT_CHARS:
        full = full[:MAX_PROMPT_CHARS] + "\n(이하생략)"
    return full


def _build_batch_prompt(batch: list, rule_scores: dict) -> str:
    total = len(batch)
    sections = []
    for n, p in enumerate(batch, 1):
        code  = p.item_code
        g_std = _DB.standard(code)
        rs    = rule_scores.get(code, -1)
        # 항목 번호와 코드를 강조한 구분선으로 격리 — 할루시네이션 방지
        item_lines = [
            f"{'━'*6}[ITEM {n}/{total}: {code}]{'━'*6}",
            f"항목명: {p.item_name}",
            f"규칙점수: {rs} | 기준: {_truncate(g_std, 300)}",
        ]
        for c in p.check_results:
            cv = _truncate((c.collected_value or "(없음)").replace("\n", " "), 300)
            item_lines.append(f" ▸ {c.sub_check[:30]}[{c.service_status}]: {cv}")
        sections.append("\n".join(item_lines))

    body = "\n\n".join(sections)
    if len(body) > MAX_PROMPT_CHARS * BATCH_SIZE:
        body = body[:MAX_PROMPT_CHARS * BATCH_SIZE] + "\n(truncated)"

    # 출력 순서를 명시하여 항목 혼동 방지
    mapping = " / ".join(f"ITEM{i+1}→{p.item_code}" for i, p in enumerate(batch))
    return (
        body
        + f"\n\n위 {total}개 항목을 반드시 ITEM 번호 순서대로 판정하세요. ({mapping})\n"
        f"JSON 배열 {total}개 출력 (item_code 생략 불가):"
    )


# ──────────────────────────────────────────────────────────
# 시스템 프롬프트 (간결)
# ──────────────────────────────────────────────────────────

SINGLE_SYSTEM = """\
주통기 Unix 서버 보안 점검 전문가.

[출력 형식 — 절대 규칙]
1. 백틱(`) · 코드블록(```json) 사용 절대 금지 — JSON 객체만 바로 출력
2. JSON 객체 1개만 출력 — 앞뒤 설명 텍스트 금지
3. 문자열 값 안 줄바꿈(\\n) 금지 — 한 줄 텍스트로 작성
4. 필드 순서 고정: item_code → result → reason → remediation

[JSON 스키마]
{"item_code":"U-XX","result":"취약|양호|해당없음","reason":"5문장판정근거","remediation":"5문장조치방법"}

[서비스 상태 판정 — 최우선 기준]
- NOT_INSTALLED → result="해당없음" (해당 서비스/패키지 미설치, 점검 불필요)
- NOT_RUNNING   → result="양호" 우선 (비활성 서비스는 공격 경로 없음, 단 설정값이 명백히 취약하면 취약)
- RUNNING       → 아래 수집값(collected_value)을 분석하여 최종 판정
- N/A           → collected_value 만으로 판단 (파일 권한·계정 설정 등)

[reason 작성 — 5문장, 비전문가도 이해 가능하게]
1문장: 이 항목이 무엇을 점검하는지 (항목명과 보안 목적)
2문장: 실제 수집된 값이 무엇인지 (collected_value를 직접 인용)
3문장: 보안 가이드라인이 요구하는 기준 값/상태가 무엇인지
4문장: 수집값이 그 기준을 충족하는지 또는 어떻게 위반하는지
5문장: 취약이면 어떤 공격/위험이 발생할 수 있는지, 양호이면 왜 안전한지

[remediation 작성 — 5문장, 실제 조치 가능하도록]
1문장: 어떤 파일 또는 설정을 변경해야 하는지
2문장: 구체적인 수정 명령어 또는 설정 값 (현재 OS 환경 기준)
3문장: 변경 적용 방법 (서비스 재시작, 권한 재적용 등)
4문장: 조치 후 검증 명령어 또는 확인 방법
5문장: 주의사항 (서비스 중단 여부, 영향 범위, 롤백 방법 등)

[판정불가 처리]
- collected_value가 비어있거나 "ERROR", "오류", "수동 점검 필요"만 있으면 result="해당없음"
- reason에 "자동 수집 불가 — 관리자 수동 점검 필요" 명시
- [스크립트판정]이 "취약"/"양호"로 제시된 경우 result는 반드시 그 값으로 출력 (변경 금지)

[할루시네이션 방지 — 반드시 준수]
- 수집된 collected_value에 없는 내용 추가 절대 금지
- 추측·가정 금지 — 실제 수집값만 근거로 사용
- 파일/서비스가 없으면 해당없음 또는 양호 처리, 임의로 취약 판정 금지

[가이드라인 우선 원칙 — 절대 위반 금지]
- 주통기 가이드라인이 유일한 정답 기준입니다. [주통기기준]/[점검포인트]에 명시된 기준값을 무시하거나 완화하지 마세요.
- "Debian/Ubuntu/RHEL 기본값", "배포판 관례", "일반 운영 환경에서 흔한 설정" 등의 이유로 가이드 기준 위반을 양호로 정당화하지 마세요.
  예시(반드시 피할 패턴): 가이드 기준 perm <= 640 인데 실제 644 라면, "Ubuntu 기본값이라 양호" 가 아니라 "기준 위반 = 취약" 입니다.
- 환경 정보(설치된 패키지, 데몬 상태, 경로 차이 등)는 '판정 결과를 어떻게 설명할지' 보조 정보로만 활용하세요. 판정 결과 자체를 환경 정보로 뒤집지 마세요.
- 가이드 기준이 모호하거나 여러 해석이 가능하면 가장 엄격한 해석을 채택하세요.
- reason 작성 시 가이드 기준값을 명시적으로 인용한 뒤(예: '가이드 기준: perm <= 640'), 수집값이 그 기준과 일치/불일치하는지 사실 그대로 비교만 하세요.\
"""

BATCH_SYSTEM = (
    "주통기 Unix 보안 점검 전문가. JSON 배열만 출력 (입력 ITEM 번호 순서 반드시 유지).\n"
    '[{"item_code":"U-XX","result":"취약|양호|해당없음",'
    '"reason":"5문장: 1)항목목적 2)수집값인용 3)기준설명 4)기준충족여부 5)위험/안전이유",'
    '"remediation":"5문장: 1)변경대상 2)명령어 3)적용방법 4)검증방법 5)주의사항"},...]\n'
    "서비스 판정 최우선: NOT_INSTALLED→해당없음 / NOT_RUNNING→양호 우선 / RUNNING→수집값분석\n"
    "⚠️ 항목 격리 규칙 (절대 준수):\n"
    "  · 각 항목은 ━━[ITEM N/T: CODE]━━ 블록 안의 데이터만 참조\n"
    "  · 다른 항목의 수집값·판단 절대 혼용 금지 — 항목 간 데이터 교차 참조 불가\n"
    "  · 입력 ITEM 순서 그대로 정확히 N개 결과 출력 (누락·순서변경·item_code 오기 불가)"
)


# ──────────────────────────────────────────────────────────
# JSON 파싱
# ──────────────────────────────────────────────────────────

def _parse_single_json(raw: str) -> dict:
    if not raw or not raw.strip():
        return {}

    # 1) 코드블록 제거 (```json ... ``` 또는 ``` ... ```)
    cleaned = re.sub(r"```(?:json)?\s*", "", raw)
    cleaned = re.sub(r"```", "", cleaned).strip()

    # 2) 직접 파싱 시도
    try:
        d = json.loads(cleaned)
        return d[0] if isinstance(d, list) and d else (d if isinstance(d, dict) else {})
    except json.JSONDecodeError:
        pass

    # 3) { } 범위 추출 후 파싱
    s, e = cleaned.find("{"), cleaned.rfind("}") + 1
    if s != -1 and e > s:
        try:
            d = json.loads(cleaned[s:e])
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            pass

    # 4) 잘린 JSON 복구 시도 (max_output_tokens 초과로 닫는 } 없을 때)
    if s != -1:
        fragment = cleaned[s:].rstrip().rstrip(",")
        if not fragment.endswith("}"):
            fragment += '"}'  # 마지막 값이 잘렸으면 닫기 시도
        try:
            d = json.loads(fragment)
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            pass

    # 5) 정규식 필드별 추출 (최후 수단)
    result = {}
    for fname, pat in [
        ("result",      r'"result"\s*:\s*"([^"]+)"'),
        ("reason",      r'"reason"\s*:\s*"((?:[^"\\]|\\.){0,500})"'),
        ("remediation", r'"remediation"\s*:\s*"((?:[^"\\]|\\.){0,500})"'),
    ]:
        m = re.search(pat, cleaned, re.DOTALL)
        if m:
            result[fname] = m.group(1)
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
# Gemini 호출 (순차 처리 — Semaphore 불필요)
# ──────────────────────────────────────────────────────────

async def _call_single_item(
    client, payload: JudgePayload, rule_score: int, label: str, script_result: str = ""
) -> dict:
    """1항목 1요청. collected_value 기반 판정."""
    prompt = _build_single_prompt(payload, rule_score, script_result)
    try:
        with open(PROMPT_DUMP_FILE, "a", encoding="utf-8") as _pf:
            _pf.write(f"\n{'='*60}\n[{payload.item_code}] {payload.item_name}\n[SYSTEM]\n{SINGLE_SYSTEM}\n[USER]\n{prompt}\n")
    except Exception:
        pass
    est_tokens = max(500, len(prompt) // 3 + 400)

    for attempt in range(1, GEMINI_MAX_RETRY + 1):
        await _rate_limit_wait(estimated_tokens=est_tokens)
        try:
            resp = await client.aio.models.generate_content(
                model=_gemini_model(),
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SINGLE_SYSTEM,
                    temperature=0.1,
                    max_output_tokens=1200,
                    thinking_config=types.ThinkingConfig(thinking_budget=0),
                    automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                ),
            )
            raw = (resp.text or "") if hasattr(resp, "text") else ""
            if not raw.strip():
                print(f"    [경고] {payload.item_code} 빈응답 → 재시도({attempt})")
                continue

            parsed = _parse_single_json(raw)
            if parsed:
                return parsed
            print(f"    [경고] {payload.item_code} 파싱실패({attempt}): {raw!r}")

        except Exception as e:
            err = str(e)
            if "429" in err or "RESOURCE_EXHAUSTED" in err:
                wait = min(300, GEMINI_RETRY_DELAY * (2 ** (attempt - 1)))
                print(f"    [429] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
                await asyncio.sleep(wait)
                _reset_rl_window()
            elif "503" in err or "UNAVAILABLE" in err:
                wait = min(60, 15 * attempt)
                print(f"    [503] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
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
                    automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
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
                wait = min(300, GEMINI_RETRY_DELAY * (2 ** (attempt - 1)))
                print(f"  [429] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
                await asyncio.sleep(wait)
                _reset_rl_window()
            elif "503" in err or "UNAVAILABLE" in err:
                wait = min(60, 15 * attempt)
                print(f"  [503] {label} → {wait:.0f}초 대기 ({attempt}/{GEMINI_MAX_RETRY})")
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
    llm_data: dict, mode: str, script_result: str = ""
) -> JudgeResult:
    """
    최종 판정 조합.
    script_result가 있으면 그 결과를 LLM이 뒤집을 수 없음 (할루시네이션 차단).
    LLM은 reason/remediation 품질 향상에만 사용.
    """
    code = payload.item_code

    # ── 규칙불가: 수집 자체가 불가 + LLM도 없음 → 판정 불가로 처리
    if script_result == "규칙불가" and not llm_data:
        reason_text = (
            f"이 항목({payload.item_name})은 자동 수집 규칙을 적용할 수 없는 환경입니다. "
            f"관리자가 직접 확인해야 합니다. "
            f"주통기 기준: {_DB.standard(code)}. "
            f"점검 포인트: {_DB.check_point(code) or '해당 항목 가이드라인 참조'}. "
            f"수동 점검 후 결과를 기록해 주세요."
        )
        return _make_result(payload, code, "해당없음", reason_text,
                            _DB.remediation(code) or "관리자 수동 확인 필요", 0.3, mode)

    # ── rule_only 모드 또는 LLM 응답 없음
    if mode == "rule_only" or not llm_data:
        if rule_score >= THRESHOLD_VULN:
            result, conf = "취약", min(0.95, rule_score / 100)
        elif rule_score < THRESHOLD_OK:
            result, conf = "양호", min(0.95, (100 - rule_score) / 100)
        else:
            result, conf = "취약", 0.55
        return _make_result(payload, code, result, rule_reason, _DB.remediation(code), round(conf, 2), mode)

    # ── LLM 응답 있음
    llm_result      = (llm_data.get("result") or "").strip()
    llm_reason      = llm_data.get("reason", "").strip()
    llm_remediation = llm_data.get("remediation", "").strip()

    reason      = llm_reason      or rule_reason
    remediation = llm_remediation or _DB.remediation(code) or "수동 확인 필요"

    # ── 스크립트 확정 판정 보호 (LLM이 결과를 뒤집을 수 없음)
    if script_result == "취약":
        result = "취약"  # LLM이 양호로 판정해도 무시
        conf   = 0.93
    elif script_result == "양호":
        result = "양호"  # LLM이 취약으로 판정해도 무시 (보수적 보호)
        conf   = 0.91
    elif llm_result in ("취약", "양호", "해당없음"):
        result = llm_result
        conf   = 0.88
    else:
        # LLM 응답 이상 → 규칙 점수 폴백
        result = "취약" if rule_score >= THRESHOLD_VULN else "양호"
        conf   = 0.60

    # LLM이 해당없음으로 판정한 경우는 항상 통과 (서비스 확인 후 판단)
    if llm_result == "해당없음" and script_result not in ("취약", "양호"):
        result = "해당없음"
        conf   = 0.90

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
        "hybrid"    스크립트판정 우선 + LLM reason/remediation 생성 (기본)
        "rule_only" LLM 없음 — 규칙/스크립트 판정만 사용
        "llm_only"  규칙 무시 — LLM이 모든 항목 판정
    """

    @staticmethod
    async def run(
        payloads: list,
        api_key: Optional[str] = None,
        mode: str = "hybrid",
    ) -> list:
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

        # ── 1단계: 규칙 분류 → 6개 버킷 ─────────────────────
        not_installed:   list = []  # 해당없음 즉시 (LLM 없음)
        certain_ok:      list = []  # 서비스 비활성 등 확정양호 즉시 (LLM 없음)
        certain_vuln:    list = []  # 스크립트 확정취약 → LLM은 text 생성만
        certain_script_ok: list = []  # 스크립트 확정양호 → LLM은 text 생성만
        rule_cannot:     list = []  # 규칙불가 → LLM 전권
        need_individual: list = []  # 패턴 불확실 → LLM 전권

        # rule_map: item_code → (score, reason, script_result)
        rule_map: dict = {}

        for p in payloads:
            score, reason, conclusive, sr = _rule_score(p)
            rule_map[p.item_code] = (score, reason, sr)

            if mode == "rule_only":
                certain_vuln.append(p) if score >= THRESHOLD_VULN else certain_ok.append(p)
            elif score == -1:
                not_installed.append((p, reason))
            elif sr == "규칙불가":
                rule_cannot.append(p)
            elif conclusive and score == 0:
                certain_ok.append(p)
            elif conclusive and score >= RULE_CERTAIN_VULN:
                certain_vuln.append(p)
            elif conclusive and sr == "양호":
                certain_script_ok.append(p)
            else:
                need_individual.append(p)

        n_llm = len(certain_vuln) + len(certain_script_ok) + len(rule_cannot) + len(need_individual)
        eta   = n_llm * REQUEST_MIN_DELAY

        print(
            f"[BatchJudge] mode={mode} | model={_gemini_model()}\n"
            f"  전체={len(payloads)} | 해당없음={len(not_installed)} | "
            f"즉시양호={len(certain_ok)} | 확정취약(LLM텍스트)={len(certain_vuln)} | "
            f"확정양호(LLM텍스트)={len(certain_script_ok)} | "
            f"규칙불가(LLM전권)={len(rule_cannot)} | 불확실(LLM전권)={len(need_individual)}\n"
            f"  LLM호출예상={n_llm}건 | 예상≈{eta:.0f}초({eta/60:.1f}분)"
        )

        results: list = []

        # ── 2단계: 미설치 → 해당없음 즉시 ───────────────────
        for p, reason in not_installed:
            reason_text = (
                f"이 항목({p.item_name})은 해당 서비스 또는 패키지가 설치되어 있지 않아 점검 대상이 아닙니다. "
                f"설치되지 않은 서비스는 공격 경로가 존재하지 않으므로 보안 위험이 없습니다. "
                f"다만 추후 해당 서비스를 설치할 경우 이 항목을 재점검해야 합니다. "
                f"주통기 가이드라인은 서비스 미설치 시 '해당없음'으로 처리합니다. "
                f"현재 환경에서는 조치가 불필요합니다."
            )
            r = _finalize(p, 0, reason, {"result": "해당없음", "reason": reason_text}, mode, sr)
            results.append(r)
            print(f"  [해당없음] {p.item_code}")

        # ── 3단계: 서비스 비활성 확정양호 즉시 ──────────────
        for p in certain_ok:
            score, reason, sr = rule_map[p.item_code]
            reason_text = (
                f"이 항목({p.item_name})은 관련 서비스가 현재 실행되고 있지 않아 보안 위협이 없는 상태입니다. "
                f"수집값 확인 결과 서비스가 비활성화(NOT_RUNNING 또는 NOT_INSTALLED) 상태입니다. "
                f"비활성화된 서비스는 외부 공격자가 접근할 수 있는 경로가 차단되어 있습니다. "
                f"주통기 가이드라인은 사용하지 않는 불필요한 서비스를 비활성화하도록 권고하므로, 현재 상태는 가이드라인을 준수합니다. "
                f"서비스를 다시 활성화할 계획이 있다면 활성화 전 이 항목을 재점검하세요."
            )
            r = _finalize(p, score, reason, {"result": "양호", "reason": reason_text}, mode, sr)
            results.append(r)
            print(f"  [즉시양호] {p.item_code} (서비스비활성)")

        key = api_key or _get_api_key()

        # LLM 호출 항목 없거나 API 키 없음 → 규칙 결과로 대체
        llm_items = certain_vuln + certain_script_ok + rule_cannot + need_individual
        if not llm_items or not key:
            if not key and llm_items:
                print("[BatchJudge] GEMINI_API_KEY 미설정 → 규칙 점수로 대체")
            for p in llm_items:
                score, reason, sr = rule_map[p.item_code]
                results.append(_finalize(p, score, reason, {}, "rule_only", sr))
            order = {p.item_code: i for i, p in enumerate(payloads)}
            results.sort(key=lambda r: order.get(r.item_code, 999))
            _print_summary(results)
            return results

        client = genai.Client(api_key=key)
        print(f"[BatchJudge] AI Studio 모드 — model={_gemini_model()}")

        async def _llm_call(p, label_prefix: str, bucket_len: int, idx: int) -> tuple:
            score, reason, sr = rule_map[p.item_code]
            label = f"{label_prefix}{idx}/{bucket_len}[{p.item_code}]"
            print(f"  {label}")
            llm_d = await _call_single_item(client, p, score, label, script_result=sr)
            r = _finalize(p, score, reason, llm_d or {}, mode, sr)
            print(f"    {p.item_code}: 스크립트={sr or '없음'} → 최종={r.result}")
            return r

        # ── 4단계: 스크립트 확정취약 → LLM reason/remediation 생성 ──
        if certain_vuln:
            print(f"\n[LLM-확정취약] {len(certain_vuln)}건 (reason/remediation 생성)...")
            for idx, p in enumerate(certain_vuln, 1):
                r = await _llm_call(p, "확정취약", len(certain_vuln), idx)
                results.append(r)

        # ── 5단계: 스크립트 확정양호 → LLM reason/remediation 생성 ──
        if certain_script_ok:
            print(f"\n[LLM-확정양호] {len(certain_script_ok)}건 (reason/remediation 생성)...")
            for idx, p in enumerate(certain_script_ok, 1):
                r = await _llm_call(p, "확정양호", len(certain_script_ok), idx)
                results.append(r)

        # ── 6단계: 규칙불가 → LLM 전권 판정 ────────────────
        if rule_cannot:
            print(f"\n[LLM-규칙불가] {len(rule_cannot)}건 (LLM 전권 판정)...")
            for idx, p in enumerate(rule_cannot, 1):
                r = await _llm_call(p, "규칙불가", len(rule_cannot), idx)
                results.append(r)

        # ── 7단계: 패턴 불확실 → LLM 전권 판정 ─────────────
        if need_individual:
            print(f"\n[LLM-불확실] {len(need_individual)}건 (LLM 전권 판정)...")
            for idx, p in enumerate(need_individual, 1):
                r = await _llm_call(p, "불확실", len(need_individual), idx)
                results.append(r)

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
    score, reason, conclusive, sr = _rule_score(payload)
    print("=" * 70)
    print(f"[디버그] {payload.item_code} | 규칙점수={score} | conclusive={conclusive} | script_result={sr!r}")
    print(f"[디버그] 규칙판단: {reason}")
    print("=" * 70)
    print("[SYSTEM PROMPT]")
    print(SINGLE_SYSTEM)
    print("-" * 70)
    print("[USER PROMPT]")
    print(_build_single_prompt(payload, score, sr))
    print(f"\n[글자수: {len(_build_single_prompt(payload, score, sr))} / {MAX_PROMPT_CHARS}]")
    print("=" * 70)


def debug_print_batch_prompt(payloads: list):
    rule_scores = {}
    for p in payloads:
        score, reason, _, sr = _rule_score(p)
        rule_scores[p.item_code] = score
        print(f"[규칙] {p.item_code}: score={score} | script={sr!r} | {reason}")
    print("=" * 70)
    print("[BATCH SYSTEM PROMPT]")
    print(BATCH_SYSTEM)
    print("-" * 70)
    print("[BATCH USER PROMPT]")
    prompt = _build_batch_prompt(payloads, rule_scores)
    print(prompt)
    print(f"\n[글자수: {len(prompt)} / {MAX_PROMPT_CHARS}]")
    print("=" * 70)
