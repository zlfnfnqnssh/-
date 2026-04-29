import subprocess
import json
import sys

# Windows에서 출력 인코딩 문제 방지
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

def check():
    category = "보안 관리"
    item_code = "W-54"
    item_name = "Dos 공격 방어 레지스트리 설정"

    cmd_str = r'''Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'SynAttackProtect','TcpMaxHalfOpen','TcpMaxHalfOpenRetried','EnableDeadGWDetect','KeepAliveTime','NoNameReleaseOnDemand' -ErrorAction SilentlyContinue | Format-List'''

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

        # 규칙 기반 판정
        result = "규칙불가"
        if full_out:
            import re
            syn_m = re.search(r'SynAttackProtect\s*[:\s]+(\d+)', full_out, re.IGNORECASE)
            dead_m = re.search(r'EnableDeadGWDetect\s*[:\s]+(\d+)', full_out, re.IGNORECASE)
            keep_m = re.search(r'KeepAliveTime\s*[:\s]+(\d+)', full_out, re.IGNORECASE)
            noname_m = re.search(r'NoNameReleaseOnDemand\s*[:\s]+(\d+)', full_out, re.IGNORECASE)
            if syn_m and dead_m and keep_m and noname_m:
                try:
                    syn_ok = int(syn_m.group(1)) >= 1
                    dead_ok = int(dead_m.group(1)) == 0
                    keep_ok = int(keep_m.group(1)) <= 300000
                    noname_ok = int(noname_m.group(1)) == 1
                    if syn_ok and dead_ok and keep_ok and noname_ok:
                        result = "양호"
                    else:
                        result = "취약"
                except ValueError:
                    pass
            else:
                result = "취약"

        output = {
            "category": category,
            "item_code": item_code,
            "item_name": item_name,
            "result": result,
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
