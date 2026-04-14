import subprocess
import json
import sys
import re

# Windows에서 출력 인코딩 문제 방지
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

def check():
    category = "보안 관리"
    item_code = "PC-07"
    item_name = "파일 시스템이 NTFS 포맷으로 설정"

    cmd_str = r'''Get-Volume | Select-Object DriveLetter,FileSystem,DriveType,Size | Format-Table -AutoSize'''

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

        # 규칙 기반 판정: 모든 볼륨이 NTFS인지 확인
        result_val = "규칙불가"
        try:
            lines = full_out.splitlines()
            has_volume = False
            has_non_ntfs = False
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                # 헤더/구분선 건너뛰기
                if "DriveLetter" in stripped or "---" in stripped:
                    continue
                # 드라이브 레터가 있는 볼륨만 검사 (알파벳으로 시작하는 줄)
                parts = stripped.split()
                if len(parts) >= 2 and re.match(r'^[A-Z]$', parts[0]):
                    fs = parts[1] if len(parts) >= 2 else ""
                    # Size가 0인 볼륨은 무시 (마지막 컬럼)
                    size_str = parts[-1] if len(parts) >= 4 else "0"
                    if size_str == "0":
                        continue
                    has_volume = True
                    if fs.upper() in ("FAT", "FAT32", "exFAT"):
                        has_non_ntfs = True
            if has_volume:
                result_val = "취약" if has_non_ntfs else "양호"
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
