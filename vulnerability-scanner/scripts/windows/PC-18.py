import subprocess
import json
import sys
import re

# Windows에서 출력 인코딩 문제 방지
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

def check():
    category = "보안 관리"
    item_code = "PC-18"
    item_name = "원격 지원 금지 정책 설정"

    cmd_str = r'''Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp','fAllowFullControl' -ErrorAction SilentlyContinue | Format-List; Get-Service msra -ErrorAction SilentlyContinue | Select-Object Name,Status'''

    try:
        # 실행 명령어 구성
        cmd = ["powershell", "-NoProfile", "-Command", cmd_str]

        def _dec(b):
            if b.startswith(b'\xff\xfe'): return b.decode('utf-16-le', errors='replace')
            if b.startswith(b'\xfe\xff'): return b.decode('utf-16-be', errors='replace')
            try: return b.decode('utf-8')
            except UnicodeDecodeError: return b.decode('cp949', errors='replace')
        result = subprocess.run(
            cmd, capture_output=True, check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        out = _dec(result.stdout).strip()
        err = _dec(result.stderr).strip()

        # 종합 출력 덤프
        full_out = out if out else err

        # 규칙 기반 판정: fAllowToGetHelp가 0이면 양호
        result_val = "규칙불가"
        try:
            match = re.search(r'fAllowToGetHelp\s*:\s*(\S+)', full_out)
            if match:
                val = match.group(1).strip()
                if val == "0":
                    result_val = "양호"
                elif val == "1":
                    result_val = "취약"
                else:
                    result_val = "규칙불가"
            elif not full_out or "fAllowToGetHelp" not in full_out:
                # 레지스트리 값이 없으면 기본값 확인 불가
                result_val = "규칙불가"
        except Exception:
            result_val = "규칙불가"

        output = {
            "category": category,
            "item_code": item_code,
            "item_name": item_name,
            "result": result_val,
            "collected_value": full_out if full_out else "명령어 실행 결과 없음/해당 설정 없음",
            "raw_output": full_out,
            "source_command": cmd_str
        }
        print(json.dumps(output, ensure_ascii=False))

    except Exception as e:
        output = {
            "category": category,
            "item_code": item_code,
            "item_name": item_name,
            "result": "규칙불가",
            "collected_value": f"코드 실행 중 앱단 오류 발생: {str(e)}",
            "raw_output": "",
            "source_command": cmd_str
        }
        print(json.dumps(output, ensure_ascii=False))

if __name__ == "__main__":
    check()
