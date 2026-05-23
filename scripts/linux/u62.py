#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-62 (중) FTP 계정 shell 제한 점검 스크립트
- FTP 기본 계정(ftp)의 쉘 설정이 /bin/false 또는 /sbin/nologin으로 제한되어 있는지 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u62_result_{scan_id}.json")


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
        print(f"[+] U-62 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인
    _svc_active = run_shell("systemctl is-active vsftpd 2>/dev/null || systemctl is-active proftpd 2>/dev/null")
    ftp_svc = "RUNNING" if _svc_active.strip() == "active" else               ("NOT_INSTALLED" if not run_shell("which vsftpd proftpd 2>/dev/null | head -1") else "NOT_RUNNING")


    passwd_file = "/etc/passwd"

    if os.path.exists(passwd_file):
        # 주통기와 동일한 명령어로 ftp 계정 정보 추출
        ftp_cmd = r"""cat /etc/passwd | grep '^ftp:'"""
        raw_ftp = run_shell(ftp_cmd)

        # ftp 계정의 쉘 부분만 추출 (마지막 필드)
        shell_cmd = r"""awk -F: '/^ftp:/ {print $7}' /etc/passwd"""
        ftp_shell = run_shell(shell_cmd).strip()

        if ftp_shell:
            collected_value = f"ftp shell: {ftp_shell}"
        else:
            collected_value = "ftp account not found"

        check_results.append({
            "sub_check": "FTP 계정 Shell 제한 점검",
            "config_file": "/etc/passwd",
            "collected_value": collected_value,
            "raw_output": raw_ftp if raw_ftp else "NOT FOUND",
            "service_status": ftp_svc,
            "source_command": "cat /etc/passwd | grep '^ftp:'"
        })

        # 쉘이 제한되어 있는지 더 명확히 표시 (false 또는 nologin 여부)
        if ftp_shell:
            restricted = "restricted" if any(x in ftp_shell for x in ["false", "nologin", "noshell"]) else "NOT restricted"
            check_results.append({
                "sub_check": "FTP 계정 Shell 제한 여부",
                "config_file": "/etc/passwd",
                "collected_value": f"shell={ftp_shell} ({restricted})",
                "raw_output": raw_ftp if raw_ftp else "NOT FOUND",
                "service_status": ftp_svc,
                "source_command": "awk -F: '/^ftp:/ {print $7}' /etc/passwd"
            })
    else:
        check_results.append({
            "sub_check": "FTP 계정 Shell 제한 점검",
            "config_file": "/etc/passwd",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": ftp_svc,
            "source_command": "cat /etc/passwd | grep '^ftp:'"
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
                "item_code": "U-62",
                "item_name": "FTP 계정 shell 제한",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
