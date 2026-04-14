import subprocess
import json
import sys
import re

# Windows에서 출력 인코딩 문제 방지
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

def check():
    category = "보안 관리"
    item_code = "PC-15"
    item_name = "OS 침입차단 기능 활성화"

    cmd_str = r'''Get-NetFirewallProfile | Select-Object Name,Enabled; Get-MpPreference -ErrorAction SilentlyContinue | Select-Object EnableNetworkProtection'''

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

        # 규칙 기반 판정: 모든 방화벽 프로필이 Enabled=True인지 확인
        result_val = "규칙불가"
        try:
            # "Enabled" 값들을 추출
            enabled_values = re.findall(r'Enabled\s*[:\s]\s*(True|False)', full_out, re.IGNORECASE)
            if enabled_values:
                if all(v.lower() == "true" for v in enabled_values):
                    result_val = "양호"
                else:
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
