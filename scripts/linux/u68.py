#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-68 (하) 로그온 시 경고 메시지 제공 점검 스크립트
- 서버 및 Telnet, FTP, SMTP, DNS 서비스의 로그온 배너(경고 메시지) 설정 여부 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u68_result_{scan_id}.json")


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
        print(f"[+] U-68 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== 주요 배너 파일 목록 (주통기 기준) ====================
    banner_files = [
        # 공통 서버 로그온 메시지
        "/etc/motd",
        "/etc/issue",
        "/etc/issue.net",
        
        # Telnet 배너
        "/etc/default/telnetd",
        "/etc/security/login.cfg",      # AIX
        "/etc/inetd.conf",              # HP-UX telnet
        
        # FTP 배너
        "/etc/default/ftpd",
        "/etc/vsftpd/vsftpd.conf",
        "/etc/ftpd/ftpaccess",
        "/etc/vsftpd.conf",
        
        # SMTP 배너
        "/etc/mail/sendmail.cf",
        "/etc/sendmail.cf",
        
        # DNS 배너
        "/etc/named.conf",
        "/etc/bind/named.conf"
    ]

    for fpath in banner_files:
        if os.path.exists(fpath):
            raw_content = run_shell(f"cat {fpath} 2>/dev/null")

            # 파일 내용이 있는지 간단히 판단 (빈 파일 구분)
            content_summary = "Banner message exists" if raw_content.strip() else "File is empty or no banner"

            check_results.append({
                "sub_check": f"로그온 경고 메시지 설정 ({fpath})",
                "config_file": fpath,
                "collected_value": content_summary,
                "raw_output": raw_content if raw_content else "EMPTY OR NOT FOUND",
                "service_status": "N/A",
                "source_command": f"cat {fpath}"
            })

    # 파일이 하나도 발견되지 않은 경우
    if not any(os.path.exists(f) for f in banner_files):
        check_results.append({
            "sub_check": "로그온 경고 메시지 전체 점검",
            "config_file": "Banner files",
            "collected_value": "No banner configuration files found",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "ls -l /etc/motd /etc/issue* /etc/default/*telnet* /etc/vsftpd* /etc/mail/sendmail.cf /etc/named.conf 2>/dev/null"
        })

    # 종합 현황 (판단에 도움이 되는 요약)
    existing_banners = [f["config_file"] for f in check_results if f["config_file"] != "Banner files" and "EMPTY" not in f["raw_output"]]

    summary = f"Found {len(existing_banners)} banner file(s)"
    if existing_banners:
        summary += " | Warning messages may be configured"
    else:
        summary += " | No warning messages configured"

    check_results.append({
        "sub_check": "로그온 경고 메시지 종합 현황",
        "config_file": "Multiple banner files",
        "collected_value": summary,
        "raw_output": "See individual sub_check results above",
        "service_status": "N/A",
        "source_command": "ls /etc/motd /etc/issue* /etc/*telnet* /etc/*ftpd* /etc/mail/sendmail.cf /etc/named.conf 2>/dev/null"
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
                "item_code": "U-68",
                "item_name": "로그온 시 경고 메시지 제공",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
