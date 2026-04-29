import subprocess
import json
import sys

# Windows에서 출력 인코딩 문제 방지
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

def check():
    category = "보안 관리"
    item_code = "W-48"
    item_name = "로그온하지 않고 시스템 종료 허용"
    
    cmd_str = r'''Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name shutdownwithoutlogon -ErrorAction SilentlyContinue'''
    
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
            m = re.search(r'shutdownwithoutlogon\s*[:\s]+(\d+)', full_out, re.IGNORECASE)
            if m:
                if m.group(1) == "0":
                    result = "양호"
                elif m.group(1) == "1":
                    result = "취약"
            else:
                if "0" in full_out and "1" not in full_out:
                    result = "양호"
                elif "1" in full_out and "0" not in full_out:
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
