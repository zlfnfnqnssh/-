from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

# mcp_server 폴더 + 프로젝트 루트 경로 추가
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from runner import ScriptRunner  # mcp_server/runner.py

# ── 환경변수 기반 설정 ─────────────────────────────────────────
DEFAULT_DSN        = os.getenv("JUTONGGI_DB_DSN",    "postgresql://admin:admin123@localhost:5432/jtk_db")
DEFAULT_REPO_ROOT  = Path(os.getenv("JUTONGGI_REPO_ROOT", ".")).resolve()
DEFAULT_GEMINI_CMD = os.getenv("GEMINI_CLI_CMD",     "gemini")

mcp = FastMCP("jutonggi-mcp")


def _runner(dsn: str | None = None) -> ScriptRunner:
    return ScriptRunner(
        dsn=dsn or DEFAULT_DSN,
        repo_root=DEFAULT_REPO_ROOT,
        gemini_cli_cmd=DEFAULT_GEMINI_CMD,
    )


# ── tool 1: 스크립트 없는 항목 조회 ───────────────────────────
@mcp.tool()
def list_missing_scripts(
    prefix:  str = "",
    os_type: str = "windows",
    dsn:     str | None = None,
) -> dict[str, Any]:
    """
    주통기 DB에는 있지만 스크립트 파일이 없는 항목을 반환합니다.
    가이드라인 정보(criteria, action 등)도 함께 반환하므로
    Gemini가 이 정보를 바탕으로 generate_check_script를 호출할 수 있습니다.

    - prefix:  PC / W / U 등 (빈 문자열이면 전체)
    - os_type: windows / linux
    """
    import psycopg
    from psycopg.rows import dict_row

    scripts_root = DEFAULT_REPO_ROOT / "scripts" / os_type

    conditions: list[str] = []
    params: list[str] = []
    if prefix:
        conditions.append("prefix = %s")
        params.append(prefix)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT code, title, severity, category,
               criteria_good, criteria_bad,
               action, action_impact, check_content
        FROM vulnerabilities
        {where}
        ORDER BY code
    """

    with psycopg.connect(dsn or DEFAULT_DSN, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

    missing = [
        dict(r) for r in rows
        if not (scripts_root / f"{r['code']}.py").exists()
    ]

    return {
        "count":   len(missing),
        "os_type": os_type,
        "items":   missing,
        "codes":   [r["code"] for r in missing],
    }


# ── tool 2: 없는 스크립트 자동 생성 + 검증 ────────────────────
@mcp.tool()
def generate_check_script(
    code:      str,
    target_os: str = "windows",
    overwrite: bool = False,
    dsn:       str | None = None,
) -> dict[str, Any]:
    """
    주통기 DB 가이드라인을 기반으로 점검 스크립트를 자동 생성합니다.
    기존 PC-01.py 스타일(JSON stdout, 양호/취약/규칙불가)에 맞게 생성하며
    문법 검사 + 실행 검증까지 수행합니다.

    - code:      점검 코드 (예: PC-03, U-01)
    - target_os: windows / linux
    - overwrite: 기존 스크립트 덮어쓰기 여부 (기본값: False)
    """
    runner = _runner(dsn)

    # 가이드라인 조회
    vuln = runner.get_vulnerability(code)
    if not vuln:
        return {"generated": False, "reason": f"DB에 {code} 항목 없음"}

    script_path = runner.resolve_script_path(code, target_os=target_os)
    script_path.parent.mkdir(parents=True, exist_ok=True)

    # 이미 존재하고 overwrite=False면 스킵
    if script_path.exists() and not overwrite:
        return {
            "code":        code,
            "script_path": str(script_path),
            "generated":   False,
            "reason":      "already_exists",
        }

    # 프롬프트 구성 + Gemini CLI 호출
    prompt = _build_generation_prompt(vuln, script_path, target_os)
    proc = subprocess.run(
        [runner.gemini_cli_cmd, "-p", prompt],
        capture_output=True,
        text=True,
        cwd=str(DEFAULT_REPO_ROOT),
        check=False,
    )

    if proc.returncode != 0:
        return {
            "code":      code,
            "generated": False,
            "reason":    "gemini_cli_error",
            "error":     proc.stderr.strip(),
        }

    # 코드 블록 추출 후 저장
    code_text = _extract_python_code(proc.stdout)
    script_path.write_text(code_text, encoding="utf-8")

    # ── 검증 1: 문법 검사 ────────────────────────────────────
    syntax = subprocess.run(
        ["python", "-m", "py_compile", str(script_path)],
        capture_output=True,
        text=True,
    )
    if syntax.returncode != 0:
        script_path.unlink(missing_ok=True)
        return {
            "code":      code,
            "generated": False,
            "reason":    "syntax_error",
            "error":     syntax.stderr.strip(),
        }

    # ── 검증 2: 실행 후 JSON stdout + 필수 필드 확인 ─────────
    run_proc = subprocess.run(
        ["python", str(script_path)],
        capture_output=True,
        timeout=30,
    )
    raw = run_proc.stdout.strip()
    sample_output = None
    last_error = "알 수 없는 오류"

    for enc in ("utf-8", "cp949"):
        try:
            parsed = json.loads(raw.decode(enc))

            # 필수 필드 확인
            required = {"item_code", "result", "collected_value"}
            missing_fields = required - set(parsed.keys())
            if missing_fields:
                raise ValueError(f"필수 필드 누락: {missing_fields}")

            # result 값 검증
            if parsed["result"] not in ("양호", "취약", "규칙불가"):
                raise ValueError(f"result 값 오류: {parsed['result']}")

            sample_output = parsed
            break
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            last_error = str(e)
            continue

    if sample_output is None:
        script_path.unlink(missing_ok=True)
        return {
            "code":      code,
            "generated": False,
            "reason":    "validation_error",
            "error":     last_error,
            "stdout":    str(raw[:300]),
        }

    return {
        "code":          code,
        "script_path":   str(script_path),
        "generated":     True,
        "validated":     True,
        "sample_output": sample_output,
    }


# ── 스크립트 생성 헬퍼 ────────────────────────────────────────

def _build_generation_prompt(
    vuln: dict[str, Any],
    script_path: Path,
    target_os: str,
) -> str:
    """기존 PC-01.py / PC-02.py 스타일에 맞는 스크립트 생성 프롬프트"""
    os_label = "Windows PowerShell" if target_os == "windows" else "Linux bash"
    cmd_hint = (
        "PowerShell 명령어로 수집 (subprocess + ['powershell', '-NoProfile', '-Command', ...])"
        if target_os == "windows"
        else "bash 명령어로 수집 (subprocess + shell=True 또는 ['bash', '-c', ...])"
    )
    clean = {k: v for k, v in vuln.items() if k not in ("raw_json", "content_hash")}

    return f"""당신은 주요정보통신기반시설(주통기) 보안 점검 스크립트 전문가입니다.
아래 주통기 가이드라인을 기반으로 Python 점검 스크립트를 작성하세요.
마크다운 코드블록 없이 실행 가능한 Python 코드만 반환하세요.

[작성 규칙]
1. stdout은 반드시 JSON 한 줄로 출력: print(json.dumps(output, ensure_ascii=False))
2. JSON 필수 필드:
   - item_code:       "{vuln.get('code', '')}"
   - item_name:       "{vuln.get('title', '')}"
   - category:        "{vuln.get('category', '')}"
   - result:          "양호" | "취약" | "규칙불가" 중 하나
   - collected_value: 수집한 실제 값과 판정 상세 내용 (문자열)
   - raw_output:      명령어 원본 출력
   - source_command:  실행한 명령어 문자열
3. {cmd_hint}
4. PowerShell stdout 인코딩 자동 감지 함수 _dec(b) 포함:
   UTF-16LE → UTF-16BE → UTF-8 → CP949 순서로 시도
5. Windows라면 상단에 추가:
   if sys.platform == 'win32': sys.stdout.reconfigure(encoding='utf-8')
6. subprocess 실행 시 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0) 추가
7. 모든 예외는 try/except로 처리하고 result="규칙불가"로 반환
8. 읽기 전용 점검만 수행 (시스템 변경 절대 금지)
9. def check(): 함수로 구현, if __name__ == "__main__": check() 형태

[판정 기준]
양호: {vuln.get('criteria_good', '')}
취약: {vuln.get('criteria_bad', '')}

[대상 OS]
{os_label}

[주통기 가이드라인 전문]
{json.dumps(clean, ensure_ascii=False, indent=2)}

[기존 스크립트 참고 예시 (PC-01.py 스타일)]
import subprocess, json, sys, re
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

def check():
    category = "계정 관리"
    item_code = "PC-01"
    item_name = "비밀번호의 주기적 변경"
    cmd_str = r'net accounts'
    try:
        def _dec(b):
            if b.startswith(b'\\xff\\xfe'): return b.decode('utf-16-le', errors='replace')
            if b.startswith(b'\\xfe\\xff'): return b.decode('utf-16-be', errors='replace')
            try: return b.decode('utf-8')
            except: return b.decode('cp949', errors='replace')
        r = subprocess.run(['powershell','-NoProfile','-Command',cmd_str],
                           capture_output=True, check=False,
                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        full_out = _dec(r.stdout).strip() or _dec(r.stderr).strip()
        result_val = "양호"  # 판정 로직 작성
        print(json.dumps({{"category":category,"item_code":item_code,
                           "item_name":item_name,"result":result_val,
                           "collected_value":full_out,"raw_output":full_out,
                           "source_command":cmd_str}}, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({{"category":category,"item_code":item_code,
                           "item_name":item_name,"result":"규칙불가",
                           "collected_value":f"오류: {{e}}","raw_output":"",
                           "source_command":cmd_str}}, ensure_ascii=False))

if __name__ == "__main__":
    check()
"""


def _extract_python_code(raw: str) -> str:
    """Gemini 응답에서 Python 코드 블록 추출"""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip() + "\n"
    return text + ("\n" if not text.endswith("\n") else "")


# ── 진입점 ────────────────────────────────────────────────────
def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()