import subprocess
import json
import sys
import re

# Windows에서 출력 인코딩 문제 방지
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

def check():
    category = "보안 관리"
    item_code = "PC-17"
    item_name = "이동식 미디어 자동 실행 방지"

    cmd_str = r'''Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue | Format-List; Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue | Format-List'''

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

        # 규칙 기반 판정: NoDriveTypeAutoRun 값이 128 이상이면 양호
        result_val = "규칙불가"
        try:
            matches = re.findall(r'NoDriveTypeAutoRun\s*:\s*(\d+)', full_out)
            if matches:
                # HKLM 또는 HKCU 중 하나라도 설정되어 있으면 가장 높은 값 기준
                max_val = max(int(m) for m in matches)
                if max_val >= 128:
                    result_val = "양호"
                else:
                    result_val = "취약"
            elif not full_out or "NoDriveTypeAutoRun" not in full_out:
                # 레지스트리 값이 없으면 자동실행 방지 미설정
                result_val = "취약"
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
