#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-20 Anonymous FTP 비활성화 점검 스크립트
- /etc/passwd에 ftp/anonymous 계정 존재 여부 확인
- collected_value는 핵심 한 줄만, raw_output은 실제 grep 결과 그대로
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u20_result_{scan_id}.json")


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
                        os_name = "Debian/Ubuntu"
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
        print(f"[+] U-20 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인
    _svc_active = run_shell("systemctl is-active vsftpd 2>/dev/null || systemctl is-active proftpd 2>/dev/null")
    ftp_svc = "RUNNING" if _svc_active.strip() == "active" else \
              ("NOT_INSTALLED" if not run_shell("which vsftpd proftpd 2>/dev/null | head -1") else "NOT_RUNNING")

    # ==================== 1. /etc/passwd에 ftp/anonymous 계정 확인 ====================
    grep_cmd = "grep -E '^ftp:|^anonymous:' /etc/passwd"
    ftp_account = run_shell(grep_cmd)

    check_results.append({
        "sub_check": "Anonymous FTP 계정 (/etc/passwd)",
        "config_file": "/etc/passwd",
        "collected_value": ftp_account.strip() if ftp_account else "FILE NOT FOUND",
        "raw_output": ftp_account if ftp_account else "ftp 또는 anonymous 계정이 존재하지 않습니다.",
        "service_status": ftp_svc,
        "source_command": grep_cmd
    })

    # ==================== 2. vsftpd 설정 확인 (Linux) ====================
    if target_os == "linux":
        vsftpd_paths = ["/etc/vsftpd/vsftpd.conf", "/etc/vsftpd.conf"]
        for path in vsftpd_paths:
            if os.path.exists(path):
                anon_line = run_shell(f"grep -i 'anonymous_enable' {path}")
                collected = anon_line.strip() if anon_line else "anonymous_enable 설정 없음"

                check_results.append({
                    "sub_check": "vsftpd Anonymous 설정",
                    "config_file": path,
                    "collected_value": collected,
                    "raw_output": anon_line if anon_line else "anonymous_enable 설정을 찾을 수 없음",
                    "service_status": ftp_svc,
                    "source_command": f"grep -i 'anonymous_enable' {path}"
                })

    # ==================== 3. proftpd 설정 확인 ====================
    proftpd_path = "/etc/proftpd/proftpd.conf"
    if os.path.exists(proftpd_path):
        proftpd_line = run_shell(f"grep -E 'User|UserAlias|Anonymous' {proftpd_path}")
        collected = proftpd_line.strip() if proftpd_line else "Anonymous 설정 없음"

        check_results.append({
            "sub_check": "proftpd Anonymous 설정",
            "config_file": proftpd_path,
            "collected_value": collected,
            "raw_output": proftpd_line if proftpd_line else "Anonymous 관련 설정을 찾을 수 없음",
            "service_status": ftp_svc,
            "source_command": f"grep -E 'User|UserAlias|Anonymous' {proftpd_path}"
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
                "item_code": "U-20",
                "item_name": "Anonymous FTP 비활성화",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
