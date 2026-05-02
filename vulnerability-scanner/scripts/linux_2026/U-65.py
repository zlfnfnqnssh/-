#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-65 (중) at 서비스 권한 설정 점검 스크립트
- at.allow, at.deny 파일의 소유자 및 권한 점검
- /usr/bin/at 명령어의 권한(SUID) 점검
"""
import subprocess
import json
import os
import platform
import stat
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u65_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_os_info() -> tuple:
    system = platform.system().lower()
    if system == "linux":
        os_type = "linux"
        os_name = "Linux"
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", encoding="utf-8") as f:
                    content = f.read().lower()
                    if "ubuntu" in content or "debian" in content:
                        os_name = "Ubuntu/Debian"
                    elif any(x in content for x in ["rhel", "centos", "fedora", "red hat"]):
                        os_name = "RHEL/CentOS"
            except:
                pass
        return os_type, os_name
    elif system == "sunos":
        return "solaris", "Solaris"
    elif system == "aix":
        return "aix", "AIX"
    elif system == "hp-ux":
        return "hpux", "HP-UX"
    else:
        return system, system.capitalize()


def save_json(result: Dict, output_dir: str, filename: str):
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] U-65 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인
    _svc_active = run_shell("systemctl is-active atd 2>/dev/null")
    at_svc = "RUNNING" if _svc_active.strip() == "active" else \
             ("NOT_INSTALLED" if not run_shell("which atd at 2>/dev/null | head -1") else "NOT_RUNNING")


    # ==================== 점검 대상 파일 목록 ====================
    at_files = [
        "/etc/at.allow",
        "/etc/at.deny",
        "/etc/cron.d/at.allow",
        "/etc/cron.d/at.deny",
        "/var/adm/cron/at.allow",      # AIX, HP-UX
        "/var/adm/cron/at.deny",       # AIX, HP-UX
        "/usr/bin/at"                  # at 명령어 자체 권한
    ]

    for fpath in at_files:
        if os.path.exists(fpath):
            # ls -l로 권한 및 소유자 확인
            ls_result = run_shell(f"ls -l {fpath}")

            try:
                st = os.stat(fpath)
                owner_name = run_shell(f"ls -l {fpath} | awk '{{print $3}}'").strip()
                perm_octal = oct(st.st_mode)[-3:]          # 640 형태
                mode_str = stat.filemode(st.st_mode)
            except:
                owner_name = "UNKNOWN"
                perm_octal = "UNKNOWN"
                mode_str = "UNKNOWN"

            collected_value = f"owner={owner_name}, permission={perm_octal} ({mode_str})"

            sub_name = "at 명령어 권한" if fpath == "/usr/bin/at" else f"at 파일 권한 ({fpath})"

            check_results.append({
                "sub_check": sub_name,
                "config_file": fpath,
                "collected_value": collected_value,
                "raw_output": ls_result if ls_result else "NOT FOUND",
                "service_status": at_svc,
                "source_command": f"ls -l {fpath}"
            })

            # at.allow / at.deny 파일인 경우 내용도 추가로 저장
            if "at.allow" in fpath or "at.deny" in fpath:
                file_content = run_shell(f"cat {fpath} 2>/dev/null")
                check_results.append({
                    "sub_check": f"at 파일 내용 ({fpath})",
                    "config_file": fpath,
                    "collected_value": "File exists" if file_content else "Empty file",
                    "raw_output": file_content if file_content else "EMPTY",
                    "service_status": at_svc,
                    "source_command": f"cat {fpath}"
                })

    # at 파일이 하나도 없을 경우
    if not any(os.path.exists(f) for f in at_files if f != "/usr/bin/at"):
        check_results.append({
            "sub_check": "at.allow / at.deny 파일 존재 여부",
            "config_file": "at control files",
            "collected_value": "No at.allow or at.deny file found",
            "raw_output": "NOT FOUND",
            "service_status": at_svc,
            "source_command": "ls -l /etc/at.* /etc/cron.d/at.* /var/adm/cron/at.* 2>/dev/null"
        })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "서비스 관리",
                "item_code": "U-65",
                "item_name": "at 서비스 권한 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
