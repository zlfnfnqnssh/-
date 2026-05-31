"""linux_patch_generator.py — Linux 전용 AI 패치 스크립트 생성·실행·재작성 모듈.

설계 의도:
  - web/routes/patch.py (다른 학생) 의 `_execute_one` 이 사용하는 engine/llm_judge.py
    는 Gemini CLI(npx) 방식이라 Node v20+ 필요 → 현재 Node v18 환경에서 깨짐.
  - 이 모듈은 google.genai Python API 를 직접 호출 (.env 의 GEMINI_API_KEY 사용)
    하여 동일 흐름(생성·안전검사·실행·재작성 3회·DB 기록)을 Linux 한정으로 재구현.
  - 호출 진입점은 integration/syeon_linux_patch_router.py 가 target_os 분기로
    Linux 만 본 모듈에 위임. Windows 는 기존 patch.py 그대로.

DB 매핑:
  · 수집 정보  : vs_scan_results        (target_os, item_name, collected_value, raw_output, source_command)
  · 판정 정보  : vs_judgments           (result, reason, remediation, patch_script)
  · 주통기 DB  : vs_guideline_items     (criteria, remediation_guide, description, importance)
  · 결과 저장  : vs_judgments.patch_script (최종 스크립트)
                vs_patch_executions    (1회 실행마다 1행)

참고:
  · engine/llm_judge.py        — 프롬프트/응답 파싱 패턴
  · integration/syeon_patch_router.py — google.genai 사용법, psycopg3 sync 패턴
  · web/routes/patch.py        — _run_patch / _safety_check / save_patch_execution
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


# ─────────────────────────────────────────────────────────────────────
# .env 자동 로드 — vulnerability-scanner/.env (단독 실행 / 웹서버 어디서든)
# ─────────────────────────────────────────────────────────────────────
_VS_ROOT = Path(__file__).resolve().parent.parent.parent / "vulnerability-scanner"
_ENV_PATH = _VS_ROOT / ".env"
if _ENV_PATH.exists():
    load_dotenv(_ENV_PATH)
else:
    load_dotenv()  # CWD fallback


# ─────────────────────────────────────────────────────────────────────
# 설정
# ─────────────────────────────────────────────────────────────────────
MAX_ATTEMPTS = int(os.getenv("LINUX_PATCH_MAX_ATTEMPTS", "3"))
PATCH_TIMEOUT_SEC = int(os.getenv("LINUX_PATCH_TIMEOUT", "120"))
GEMINI_MODEL_DEFAULT = "gemini-2.5-flash"

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# 안전 검사 — 위험한 bash 패턴 차단
# ─────────────────────────────────────────────────────────────────────
_DANGEROUS_PATTERNS = [
    (r"\brm\s+-rf\s+/(\s|$|\*)",        "루트 디렉토리 삭제"),
    (r"\brm\s+-rf\s+/\w",               "최상위 디렉토리 삭제"),
    (r"\bdd\s+if=.*of=/dev/(sd[a-z]|nvme|hd[a-z])", "raw 디스크 덮어쓰기"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
    (r"\b(curl|wget)\b.+\|\s*(bash|sh|zsh|fish)\b", "외부 스크립트 파이프 실행"),
    (r"\bmkfs\.[a-z0-9]+\b",            "파일 시스템 포맷"),
    (r"\b(shutdown|reboot|poweroff|halt)\b", "시스템 종료/재시작"),
    (r"\b>\s*/dev/sd[a-z]",             "디스크 덮어쓰기"),
    (r"\bchmod\s+-R\s+0?77\d\s+/(\s|$)", "루트 권한 777"),
    (r"\bchown\s+-R\s+\w+\s+/(\s|$)",   "루트 소유자 변경"),
    (r"\buserdel\s+root\b",             "root 계정 삭제"),
    (r"\bpasswd\s+-d\s+root\b",         "root 패스워드 제거"),
]


def safety_check(script: str) -> tuple[bool, str]:
    """위험 패턴 발견시 (False, 사유). 통과시 (True, '')."""
    if not script.strip():
        return False, "스크립트가 비어있음"
    for pat, reason in _DANGEROUS_PATTERNS:
        if re.search(pat, script, re.IGNORECASE | re.MULTILINE):
            return False, f"위험 패턴 차단: {reason}"
    return True, ""


# ─────────────────────────────────────────────────────────────────────
# DB 헬퍼 — psycopg3 sync (공용 SQLAlchemy 풀 미접촉)
# ─────────────────────────────────────────────────────────────────────
def _dsn() -> str:
    return (
        f"host={os.getenv('PG_HOST', 'localhost')} "
        f"port={os.getenv('PG_PORT', '5432')} "
        f"user={os.getenv('PG_USER', 'postgres')} "
        f"password={os.getenv('PG_PASSWORD', '')} "
        f"dbname={os.getenv('PG_DB', 'forensic_db')}"
    )


def _fetch_context(scan_id: str, item_code: str) -> Optional[dict]:
    """vs_scan_results + vs_judgments + vs_guideline_items (현재 버전) 조인 조회."""
    import psycopg  # type: ignore
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT sr.target_os, sr.category, sr.item_name,
                   sr.collected_value, sr.raw_output, sr.source_command,
                   j.result, j.reason, j.remediation, j.patch_script
              FROM vs_scan_results sr
              LEFT JOIN vs_judgments j
                ON j.scan_id = sr.scan_id AND j.item_code = sr.item_code
             WHERE sr.scan_id = %s AND sr.item_code = %s
             LIMIT 1
            """,
            (scan_id, item_code),
        )
        r = cur.fetchone()
        if not r:
            return None
        target_os, category, item_name, collected_value, raw_output, \
            source_command, j_result, j_reason, j_remediation, j_patch = r

        cur.execute(
            """
            SELECT gi.criteria, gi.remediation_guide, gi.description,
                   gi.importance, gi.check_examples
              FROM vs_guideline_items gi
              JOIN vs_guideline_versions gv ON gv.version_id = gi.version_id
             WHERE gi.item_code = %s
               AND LOWER(COALESCE(gi.target_os, '')) IN ('linux', '')
               AND gv.is_current = TRUE
             LIMIT 1
            """,
            (item_code,),
        )
        g = cur.fetchone()
        guideline = {
            "criteria":          (g[0] if g else "") or "",
            "remediation_guide": (g[1] if g else "") or "",
            "description":       (g[2] if g else "") or "",
            "importance":        (g[3] if g else "") or "",
            "check_examples":    (g[4] if g else "") or "",
        }

    return {
        "target_os":       target_os or "",
        "category":        category or "",
        "item_name":       item_name or item_code,
        "collected_value": collected_value or "",
        "raw_output":      raw_output or "",
        "source_command":  source_command or "",
        "judgment_result": j_result or "",
        "judgment_reason": j_reason or "",
        "judgment_remediation": j_remediation or "",
        "existing_patch_script": j_patch or "",
        "guideline":       guideline,
    }


def _update_judgment_patch(scan_id: str, item_code: str, patch_script: str) -> None:
    import psycopg
    with psycopg.connect(_dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE vs_judgments SET patch_script=%s WHERE scan_id=%s AND item_code=%s",
                (patch_script, scan_id, item_code),
            )
        conn.commit()


def _insert_patch_execution(row: dict) -> None:
    """vs_patch_executions 1행 기록."""
    import psycopg
    with psycopg.connect(_dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO vs_patch_executions
                (user_id, scan_id, machine_id, target_os, item_code, item_name,
                 judgment_result, mode, patch_script, rewritten, attempts,
                 final_returncode, success, stdout, stderr,
                 safety_blocked, block_reason)
                VALUES (%s,%s,%s,%s,%s,%s, %s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s)
                """,
                (
                    row["user_id"], row["scan_id"], row.get("machine_id", ""),
                    row["target_os"], row["item_code"], row["item_name"],
                    row.get("judgment_result", ""), row.get("mode", "single"),
                    row.get("patch_script", "")[:50000],
                    bool(row.get("rewritten", False)),
                    int(row.get("attempts", 1)),
                    int(row.get("final_returncode", -1)),
                    bool(row.get("success", False)),
                    (row.get("stdout") or "")[:8000],
                    (row.get("stderr") or "")[:8000],
                    bool(row.get("safety_blocked", False)),
                    (row.get("block_reason") or "")[:2000],
                ),
            )
        conn.commit()


# ─────────────────────────────────────────────────────────────────────
# bash 실행 — sudo 지원 (웹 파이프라인이 받은 root password 그대로 사용)
# ─────────────────────────────────────────────────────────────────────
# exit_code 가 0 이라도 stderr 에 아래 패턴이 보이면 실패로 간주 → 재작성 트리거.
_STDERR_FAILURE_PATTERNS = [
    r"\bpermission denied\b",
    r"\boperation not permitted\b",
    r"\bcommand not found\b",
    r"\bsyntax error\b",
    r"\bunrecognized option\b",
    r"\binvalid argument\b",
    r"\bcannot (create|access|open|read|write|remove|stat)\b",
    r"\bfailed to\b",
    r"\bsudo:.*incorrect password\b",
    r"\bsudo:.*a password is required\b",
]


def exec_failed(exec_result: dict) -> tuple[bool, str]:
    """실행 결과를 보고 (실패여부, 사유). exit 0 이라도 stderr 패턴이면 재작성."""
    if exec_result.get("timed_out"):
        return True, "실행 타임아웃"
    rc = exec_result.get("returncode", -1)
    if rc != 0:
        return True, f"종료 코드 {rc}"
    stderr_lower = (exec_result.get("stderr") or "").lower()
    for pat in _STDERR_FAILURE_PATTERNS:
        if re.search(pat, stderr_lower):
            return True, f"stderr 실패 패턴 감지: {pat}"
    return False, ""


def run_bash(
    script: str,
    timeout: int = PATCH_TIMEOUT_SEC,
    sudo_password: str = "",
) -> dict:
    """임시 .sh 파일에 저장 후 bash 실행. sudo_password 가 있으면 `sudo -S` 사용.

    웹 Linux 파이프라인이 스캔 시 받은 root password 를 그대로 재사용한다
    (scan.py 의 sudo_password 와 동일 출처 — SYEON_SUDO_PASSWORD env var 또는 body).
    """
    tmp = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8")
    try:
        # shebang 없으면 보강. 단 set -e 는 자동 주입하지 않는다.
        # (이전에 자동 주입했더니 systemctl is-active 등 검증 명령이 비제로 반환할 때
        #  스크립트가 조용히 종료되어 stderr 비어있는 채로 exit 3/4 만 남는 문제 발생.)
        if script.startswith("#!"):
            content = script
        else:
            content = "#!/bin/bash\n" + script
        tmp.write(content)
        tmp.flush()
        tmp.close()
        os.chmod(tmp.name, 0o700)

        stdin_data: Optional[str] = None
        if sudo_password:
            # sudo -S : stdin 으로 비밀번호 입력 (prompt 는 stderr 로 -p '' 처리)
            cmd = ["sudo", "-S", "-p", "", "bash", tmp.name]
            stdin_data = sudo_password + "\n"
        elif os.geteuid() == 0:
            # 이미 root 면 sudo 불필요
            cmd = ["bash", tmp.name]
        else:
            # 비밀번호 미제공 + non-root → passwordless sudo 시도, 실패해도 그대로 보고
            cmd = ["sudo", "-n", "bash", tmp.name]

        try:
            r = subprocess.run(
                cmd,
                input=stdin_data,
                capture_output=True, text=True, timeout=timeout,
            )
            stderr_clean = (r.stderr or "")
            # 비제로 종료인데 stderr 가 비어있는 케이스: set -e 가 검증명령에서 죽었거나
            # 어떤 명령이 silent 하게 비제로를 반환한 것. UI 가 '알 수 없는 오류' 로 보여서
            # 진단이 어렵기 때문에 stdout 끝 라인을 힌트로 첨부한다.
            if r.returncode != 0 and not stderr_clean.strip():
                tail_stdout = (r.stdout or "").strip().splitlines()
                hint_lines = tail_stdout[-3:] if tail_stdout else []
                stderr_clean = (
                    f"(stderr 비어있음 / exit={r.returncode}) "
                    f"— set -e 등으로 silent 종료된 가능성. "
                    f"stdout 마지막 라인: {' | '.join(hint_lines) if hint_lines else '(없음)'}"
                )
            return {
                "returncode": r.returncode,
                "stdout": r.stdout or "",
                "stderr": stderr_clean,
                "timed_out": False,
                "cmd_used": " ".join(cmd[:2]) + " bash <script>",
            }
        except subprocess.TimeoutExpired as e:
            return {
                "returncode": -1,
                "stdout": (e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")),
                "stderr": f"실행 타임아웃 ({timeout}s)",
                "timed_out": True,
                "cmd_used": " ".join(cmd[:2]),
            }
        except Exception as e:
            return {"returncode": -1, "stdout": "", "stderr": f"실행 오류: {e}", "timed_out": False}
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────
# 프롬프트 생성
# ─────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = (
    "당신은 주요정보통신기반시설(주통기) 보안 패치 전문가입니다.\n"
    "\n"
    "[최우선 원칙 — 절대 위반 금지]\n"
    "1. 주통기 가이드라인이 유일한 정답 기준입니다. 가이드라인을 무시·완화·재해석하지 마세요.\n"
    "2. 'OS 기본값', 'Debian/Ubuntu/RHEL 의 관례적 설정', '일반적 운영 환경' 같은 이유로 "
    "가이드라인 기준에서 벗어난 상태를 정당화하지 마세요. "
    "예: 가이드 기준이 perm <= 640 이면, 644 는 '배포판 기본값이라 양호' 가 아니라 "
    "'가이드 기준 위반 = 취약' 입니다. 패치는 가이드 기준에 맞추도록 작성하세요.\n"
    "3. 환경 컨텍스트(설치 패키지, 사용 중인 데몬, 경로 차이 등) 는 패치 동작이 "
    "올바르도록 '어떻게 수정할지' 결정에만 활용하세요. '왜 수정하지 않아도 되는지' "
    "정당화하는 용도로는 절대 사용 금지.\n"
    "4. 가이드라인에 명시되지 않은 추측·자체 판단·관습적 예외 도입 금지. "
    "가이드라인이 모호하면 가장 엄격한 해석을 선택하세요.\n"
    "\n"
    "[bash 스크립트 작성 — 절대 위반 금지]\n"
    "★ `set -e` 사용 금지 ★ — 이 환경에서는 `systemctl is-active`, `systemctl status`, "
    "`grep`, `test`, `[ ... ]` 등 정상 동작 중에도 비제로 종료를 반환하는 명령을 자주 사용합니다. "
    "`set -e` 가 켜져있으면 그런 라인에서 스크립트가 stderr 없이 조용히 죽어 디버깅 불가. "
    "실제로 패치가 실패해야 하는 라인만 `cmd || { echo '사유' >&2; exit 1; }` 처럼 명시 처리하세요. "
    "검증/탐지 목적 명령은 `cmd || true` 로 감싸 비제로 무시.\n"
    "\n"
    "[출력 형식]\n"
    "JSON 한 줄({\"patch_script\":\"...\",\"explanation\":\"...\"}) 만 출력하세요. "
    "마크다운 코드블록, 인사말, 설명 문장 절대 금지."
)


def _truncate(text: str, limit: int) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…(이하 생략, 총 {len(text)}자)"


def build_prompt(ctx: dict, attempt: int, prev_script: str = "",
                 prev_exec: dict | None = None) -> str:
    """가이드라인 + raw_output + 이전 시도 에러까지 포함한 프롬프트."""
    g = ctx.get("guideline") or {}
    parts: list[str] = [
        f"[항목코드] {ctx['item_code']}",
        f"[항목명]   {ctx['item_name']}",
        f"[OS]      linux",
    ]
    if g.get("importance"):
        parts.append(f"[중요도]   {g['importance']}")
    if g.get("description"):
        parts.append("\n[주통기 설명]\n" + _truncate(g["description"], 800))
    if g.get("criteria"):
        parts.append("\n[주통기 판단 기준]\n" + _truncate(g["criteria"], 800))
    if g.get("remediation_guide"):
        parts.append("\n[주통기 조치 방법]\n" + _truncate(g["remediation_guide"], 1200))
    elif ctx.get("judgment_remediation"):
        parts.append("\n[LLM 판정 조치 방법]\n" + _truncate(ctx["judgment_remediation"], 800))
    if g.get("check_examples"):
        parts.append("\n[점검 및 조치 예시]\n" + _truncate(g["check_examples"], 600))

    parts.append("\n[현재 수집된 상태 — collected_value]\n" + _truncate(ctx["collected_value"], 1500))
    if ctx.get("raw_output"):
        parts.append("\n[원본 명령어 출력 — raw_output]\n" + _truncate(ctx["raw_output"], 2000))
    if ctx.get("source_command"):
        parts.append(f"\n[수집 명령어] {ctx['source_command']}")
    if ctx.get("judgment_reason"):
        parts.append("\n[판정 근거]\n" + _truncate(ctx["judgment_reason"], 600))

    if attempt > 1 and prev_exec is not None:
        fail_reason = prev_exec.get("failure_reason") or "(미상)"
        prev_stderr = prev_exec.get("stderr") or ""
        prev_stdout = prev_exec.get("stdout") or ""
        prev_rc = prev_exec.get("returncode")

        # set -e 가 silent 하게 죽인 패턴 감지 — LLM 에게 명시적으로 경고
        silent_die_hint = ""
        if prev_rc not in (0, None) and not prev_stderr.strip():
            silent_die_hint = (
                "\n  ★ 진단 힌트: stderr 가 비어있고 종료코드만 비제로입니다. "
                "이는 거의 확실하게 `set -e` 가 켜진 스크립트에서 검증 명령 "
                "(systemctl is-active, systemctl status, grep 등) 이 비제로를 반환해 "
                "조용히 종료된 케이스입니다. 다음 재작성에서:\n"
                "    (a) `set -e` 를 절대 사용하지 마세요.\n"
                "    (b) 비제로를 정상으로 보는 검증 명령은 `|| true` 로 감싸세요.\n"
                "    (c) 실제로 실패 여부를 확인해야 하는 명령만 명시적으로 `|| { echo 사유 >&2; exit 1; }` 처리."
            )
        elif "inactive" in prev_stdout.lower() and prev_rc != 0:
            silent_die_hint = (
                "\n  ★ 진단 힌트: stdout 에 'inactive' 가 보이고 비제로 종료입니다. "
                "`systemctl is-active <svc>` 가 inactive 일 때 exit 3 을 반환했을 가능성. "
                "비활성 서비스 자체는 패치 동작과 무관할 수 있으니 "
                "`systemctl is-active rsyslog || true` 형태로 감싸세요."
            )

        parts.append(
            "\n[직전 시도 실패 — 재작성 필요]\n"
            f"  - 실패 사유  : {fail_reason}\n"
            f"  - 종료코드   : {prev_rc}\n"
            f"  - 타임아웃   : {prev_exec.get('timed_out', False)}\n"
            f"  - stderr     : {_truncate(prev_stderr, 800)}\n"
            f"  - stdout     : {_truncate(prev_stdout, 400)}"
            f"{silent_die_hint}\n\n"
            f"[직전 patch_script]\n{_truncate(prev_script, 1200)}\n\n"
            "위 에러를 분석해서, 같은 목적(주통기 항목 양호화)을 달성하면서 "
            "에러 원인을 제거한 새로운 bash 스크립트를 작성하세요. "
            "특히 'permission denied' 류 에러면 권한 확인/sudo 호출/경로 수정을, "
            "'command not found' 면 패키지 매니저로 사전 설치를, "
            "'syntax error' 면 따옴표/이스케이프를 점검하세요."
        )

    parts.append(
        "\n## 가이드라인 우선 원칙 (반드시 준수)\n"
        "- 위 [주통기 판단 기준] / [주통기 조치 방법] 의 요구사항을 그대로 충족시키는 패치를 작성하세요.\n"
        "- 현재 환경의 기본값(예: 배포판 default permission, 패키지 기본 설정) 이 가이드 기준과 다르면, "
        "가이드 기준으로 맞추는 것이 정답입니다. '환경상 기본이라 안전하다' 같은 판단으로 패치를 생략하지 마세요.\n"
        "- 가이드 기준이 모호한 경우 가장 엄격한 해석으로 패치하세요.\n"
        "- 환경 정보(설치된 데몬, 파일 경로, 패키지 매니저 등) 는 패치 동작을 정확히 짜기 위한 컨텍스트로만 사용하세요.\n"
        "\n## 응답 형식 (JSON 1줄, 마크다운 금지)\n"
        '{"patch_script":"실행 가능한 bash 스크립트 (자동화 불가시 빈 문자열)",'
        '"explanation":"한 문장 요약 — 어떤 가이드 기준을 어떻게 충족시키는지 명시"}\n\n'
        "## 작성 규칙\n"
        "1. bash 명령어만 사용 (관리자 권한 sudo 로 실행됨을 가정)\n"
        "2. ★ `set -e` 사용 금지 ★ — 이 환경에서는 `systemctl is-active`/`status`/`grep` 등 "
        "정상적으로 비제로 종료할 수 있는 명령을 검증 단계에서 자주 씁니다. set -e 가 켜져있으면 "
        "조용히 스크립트가 죽어 stderr 도 비어버립니다.\n"
        "3. 명령 실패가 진짜 에러인 경우만 처리하세요. 예:\n"
        "     chmod 640 /etc/x.conf || { echo 'chmod 실패' >&2; exit 1; }\n"
        "   검증 명령이 비제로를 반환해도 패치 자체에는 문제가 없는 경우는 무시:\n"
        "     systemctl is-active rsyslog || true\n"
        "4. 위험 명령 (rm -rf /, dd, mkfs, shutdown, fork bomb 등) 절대 금지\n"
        "5. 정책 판단이 본질적으로 필요한 항목은 patch_script 를 빈 문자열로 두고 explanation 에 "
        "어떤 가이드 기준이 왜 정책 판단을 요구하는지 명시\n"
        "6. 마지막에 핵심 검증 명령 1줄 포함 권장 (예: stat -c '%a' /etc/x.conf) — 단 `|| true` 로 wrap 하거나 "
        "결과가 비제로여도 무방하도록 작성\n"
        "7. 스크립트는 멱등(idempotent) 하게 — 이미 양호 상태인 시스템에 재실행해도 무사 종료"
    )
    return "\n".join(parts)


def parse_llm_response(raw: str) -> tuple[str, str]:
    """LLM 응답에서 patch_script, explanation 추출."""
    cleaned = re.sub(r"```(?:json)?\s*", "", raw or "").strip().rstrip("`").strip()
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not m:
        return "", ""
    try:
        obj = json.loads(m.group(0))
        return (obj.get("patch_script") or "").strip(), (obj.get("explanation") or "").strip()
    except json.JSONDecodeError:
        ps = re.search(r'"patch_script"\s*:\s*"((?:[^"\\]|\\.)*)"', cleaned, re.DOTALL)
        ex = re.search(r'"explanation"\s*:\s*"((?:[^"\\]|\\.)*)"', cleaned, re.DOTALL)
        return (
            (ps.group(1).encode().decode("unicode_escape", errors="replace").strip() if ps else ""),
            (ex.group(1) if ex else ""),
        )


# ─────────────────────────────────────────────────────────────────────
# 메인 클래스
# ─────────────────────────────────────────────────────────────────────
class LinuxPatchGenerator:
    """Linux 한정 AI 패치 생성 + 실행 + 재작성 루프.

    사용 예 (FastAPI 라우터에서):
        gen = LinuxPatchGenerator()
        result = await gen.run(scan_id, item_code, user_id, machine_id, mode="single",
                               execute=True)
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.model = model or os.getenv("GEMINI_MODEL", GEMINI_MODEL_DEFAULT)
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY 미설정 (.env 확인)")
        try:
            from google import genai  # type: ignore
            self._client = genai.Client(api_key=self.api_key)
        except ImportError as e:
            raise RuntimeError(f"google.genai 모듈 미설치: pip install google-genai ({e})")
        return self._client

    def _call_gemini_sync(self, prompt: str) -> str:
        from google.genai import types  # type: ignore
        client = self._ensure_client()
        resp = client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
                max_output_tokens=1500,
                thinking_config=types.ThinkingConfig(thinking_budget=0),
            ),
        )
        return (resp.text or "").strip() if hasattr(resp, "text") else ""

    async def _call_gemini(self, prompt: str) -> str:
        # 동기 SDK 를 executor 에서 (FastAPI 이벤트 루프 블로킹 방지)
        loop = asyncio.get_event_loop()
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                return await loop.run_in_executor(None, self._call_gemini_sync, prompt)
            except Exception as e:
                msg = str(e)
                if ("429" in msg or "RESOURCE_EXHAUSTED" in msg) and attempt < MAX_ATTEMPTS:
                    wait = 60 * attempt
                    logger.warning("[LinuxPatch] Gemini 429 → %ds 대기 (%d/%d)", wait, attempt, MAX_ATTEMPTS)
                    await asyncio.sleep(wait)
                    continue
                raise

    async def run(
        self,
        scan_id: str,
        item_code: str,
        user_id: str,
        machine_id: str = "",
        mode: str = "single",
        execute: bool = True,
        sudo_password: str = "",
    ) -> dict:
        """패치 생성 + (기본) 실행 + 재작성 3회 루프.

        Args:
          execute: True(기본) 면 생성→안전검사→bash 실행 (sudo) →실패시 LLM 에 에러
                   피드백하고 재작성 (최대 3회).
                   False 면 1회만 생성하고 vs_judgments.patch_script 갱신 후 종료.
          sudo_password: 비어있지 않으면 `sudo -S` 로 root 권한 실행. 비어있으면
                   환경변수 SYEON_SUDO_PASSWORD 폴백 (웹 스캔 시 저장된 값과 동일).
                   둘 다 없으면 passwordless sudo 시도 (-n).

        반환 dict 키:
          success, executed, attempts, rewritten, patch_script, explanation,
          stdout, stderr, returncode, blocked, skipped, reason
        """
        loop = asyncio.get_event_loop()

        # sudo password 폴백: 인자 → env var (웹 스캔이 채워둔 값 재사용)
        if not sudo_password:
            sudo_password = os.getenv("SYEON_SUDO_PASSWORD", "")

        # 1. 컨텍스트 조회
        ctx = await loop.run_in_executor(None, _fetch_context, scan_id, item_code)
        if not ctx:
            return {"success": False, "skipped": True, "reason": "scan/item 찾을 수 없음"}
        ctx["item_code"] = item_code

        # 2. target_os 검증 — Linux 만 처리
        if (ctx["target_os"] or "").lower() != "linux":
            return {
                "success": False, "skipped": True,
                "reason": f"target_os={ctx['target_os']!r} — Linux 전용 모듈",
            }

        # 3. 판정 검증 — 취약만 실행
        if ctx["judgment_result"] != "취약":
            return {
                "success": False, "skipped": True,
                "reason": f"취약 판정 아님 (현재: {ctx['judgment_result'] or '(없음)'})",
                "judgment_result": ctx["judgment_result"],
            }

        # 4. 메인 루프
        prev_script: str = ""
        prev_exec: dict | None = None
        final_script: str = ""
        final_explanation: str = ""
        attempts_used: int = 0
        rewritten_flag: bool = False
        executed_flag: bool = False
        last_exec: dict = {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False}

        for attempt in range(1, MAX_ATTEMPTS + 1):
            attempts_used = attempt
            is_rewrite = (attempt > 1)
            if is_rewrite:
                rewritten_flag = True

            # 4-a. 프롬프트 구성: attempt 1 은 기존 patch_script 가 있으면 재사용 시도
            if attempt == 1 and ctx["existing_patch_script"]:
                # 기존 스크립트 그대로 1회 실행 시도. LLM 호출 생략.
                candidate = ctx["existing_patch_script"]
                explanation = "(기존 patch_script 재사용)"
            else:
                prompt = build_prompt(ctx, attempt, prev_script, prev_exec)
                try:
                    raw = await self._call_gemini(prompt)
                except Exception as e:
                    logger.exception("[LinuxPatch] Gemini 호출 실패")
                    last_exec = {"returncode": -1, "stdout": "", "stderr": f"Gemini 호출 실패: {e}", "timed_out": False}
                    continue
                candidate, explanation = parse_llm_response(raw)
                if not candidate:
                    # LLM 이 자동화 불가 판단 (빈 스크립트) — 루프 중단, 정책 항목
                    final_script = ""
                    final_explanation = explanation or "LLM 이 자동화 불가로 판단"
                    break

            final_script = candidate
            final_explanation = explanation

            # 4-b. 안전 검사
            safe, why = safety_check(candidate)
            if not safe:
                logger.warning("[LinuxPatch] %s 안전장치 차단: %s", item_code, why)
                # 차단 기록 후 즉시 종료
                await loop.run_in_executor(None, _insert_patch_execution, {
                    "user_id": user_id, "scan_id": scan_id, "machine_id": machine_id,
                    "target_os": "linux", "item_code": item_code, "item_name": ctx["item_name"],
                    "judgment_result": ctx["judgment_result"], "mode": mode,
                    "patch_script": candidate, "rewritten": rewritten_flag, "attempts": attempt,
                    "final_returncode": -1, "success": False, "stdout": "", "stderr": "",
                    "safety_blocked": True, "block_reason": why,
                })
                return {
                    "success": False, "blocked": True, "reason": why,
                    "patch_script": candidate, "attempts": attempt,
                    "rewritten": rewritten_flag, "executed": False,
                }

            # 4-c. execute=False 면 생성만 하고 저장 후 종료 (regenerate 용)
            if not execute:
                await loop.run_in_executor(None, _update_judgment_patch, scan_id, item_code, candidate)
                return {
                    "success": True, "executed": False,
                    "patch_script": candidate, "explanation": explanation,
                    "attempts": attempt, "rewritten": rewritten_flag,
                }

            # 4-d. bash 실행 (sudo_password 있으면 sudo -S, 없으면 sudo -n 또는 root 직접)
            exec_result = await loop.run_in_executor(
                None,
                lambda c=candidate: run_bash(c, sudo_password=sudo_password),
            )
            executed_flag = True
            last_exec = exec_result
            failed, fail_reason = exec_failed(exec_result)
            logger.info("[LinuxPatch] %s 시도 %d/%d rc=%d failed=%s reason=%s",
                        item_code, attempt, MAX_ATTEMPTS,
                        exec_result["returncode"], failed, fail_reason)

            if not failed:
                # 성공 (exit 0 + stderr 깨끗) → patch_script 갱신 + 이력 저장 + 즉시 반환
                await loop.run_in_executor(None, _update_judgment_patch, scan_id, item_code, candidate)
                await loop.run_in_executor(None, _insert_patch_execution, {
                    "user_id": user_id, "scan_id": scan_id, "machine_id": machine_id,
                    "target_os": "linux", "item_code": item_code, "item_name": ctx["item_name"],
                    "judgment_result": ctx["judgment_result"], "mode": mode,
                    "patch_script": candidate, "rewritten": rewritten_flag, "attempts": attempt,
                    "final_returncode": 0, "success": True,
                    "stdout": exec_result["stdout"], "stderr": exec_result["stderr"],
                    "safety_blocked": False, "block_reason": "",
                })
                return {
                    "success": True, "executed": True,
                    "patch_script": candidate, "explanation": explanation,
                    "attempts": attempt, "rewritten": rewritten_flag,
                    "returncode": 0, "stdout": exec_result["stdout"], "stderr": exec_result["stderr"],
                }

            # 실패 → prev 에 담아서 다음 attempt 에 LLM 에게 보여줌 (재작성 트리거)
            prev_script = candidate
            # prev_exec 에 실패 사유 주입 (exit 0 이지만 stderr 실패 케이스도 포함)
            prev_exec = dict(exec_result)
            prev_exec["failure_reason"] = fail_reason

        # 4-e. 루프 종료 — 모두 실패
        await loop.run_in_executor(None, _update_judgment_patch, scan_id, item_code, final_script)
        await loop.run_in_executor(None, _insert_patch_execution, {
            "user_id": user_id, "scan_id": scan_id, "machine_id": machine_id,
            "target_os": "linux", "item_code": item_code, "item_name": ctx["item_name"],
            "judgment_result": ctx["judgment_result"], "mode": mode,
            "patch_script": final_script, "rewritten": rewritten_flag, "attempts": attempts_used,
            "final_returncode": last_exec.get("returncode", -1), "success": False,
            "stdout": last_exec.get("stdout", ""), "stderr": last_exec.get("stderr", ""),
            "safety_blocked": False, "block_reason": "",
        })
        return {
            "success": False, "executed": executed_flag,
            "patch_script": final_script, "explanation": final_explanation,
            "attempts": attempts_used, "rewritten": rewritten_flag,
            "returncode": last_exec.get("returncode", -1),
            "stdout": last_exec.get("stdout", ""), "stderr": last_exec.get("stderr", ""),
            "reason": (
                final_explanation or
                f"{MAX_ATTEMPTS}회 시도 모두 실패 (마지막 rc={last_exec.get('returncode')})"
            ),
        }


# ─────────────────────────────────────────────────────────────────────
# CLI (테스트용)
# ─────────────────────────────────────────────────────────────────────
def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(description="Linux 패치 스크립트 생성·실행·재작성")
    p.add_argument("--scan-id", required=True)
    p.add_argument("--item-code", required=True)
    p.add_argument("--user-id", default="cli")
    p.add_argument("--machine-id", default="")
    p.add_argument("--mode", default="single")
    p.add_argument("--no-execute", action="store_true", help="생성만, 실행 안 함")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    gen = LinuxPatchGenerator()
    try:
        res = asyncio.run(gen.run(
            args.scan_id, args.item_code, args.user_id,
            machine_id=args.machine_id, mode=args.mode,
            execute=not args.no_execute,
        ))
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("success") else 2


if __name__ == "__main__":
    sys.exit(_cli())
