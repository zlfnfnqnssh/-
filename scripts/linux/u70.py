#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-70 (중) expn, vrfy 명령어 제한 점검 스크립트
- SMTP 서비스(sendmail)에서 VRFY, EXPN 명령어 제한 설정(noexpn, novrfy, goaway) 여부 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u70_result_{scan_id}.json")


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
        print(f"[+] U-70 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # SMTP 설정 파일 목록 (주통기 기준)
    sendmail_files = [
        "/etc/mail/sendmail.cf",
        "/etc/sendmail.cf",
        "/etc/mail/sendmail.cf.local"
    ]

    privacy_options_found = False

    for config_file in sendmail_files:
        if os.path.exists(config_file):
            raw_content = run_shell(f"cat {config_file} 2>/dev/null")

            # PrivacyOptions 라인 찾기
            privacy_cmd = f"grep -E '^[[:space:]]*O[[:space:]]*PrivacyOptions' {config_file} 2>/dev/null || true"
            privacy_line = run_shell(privacy_cmd).strip()

            if privacy_line:
                privacy_options_found = True
                collected = privacy_line
            else:
                collected = "PrivacyOptions not set"

            check_results.append({
                "sub_check": f"SMTP PrivacyOptions 설정 ({config_file})",
                "config_file": config_file,
                "collected_value": collected,
                "raw_output": raw_content if raw_content else "NOT FOUND",
                "service_status": "N/A",
                "source_command": f"grep -E 'PrivacyOptions' {config_file}"
            })

            # goaway, noexpn, novrfy 키워드 존재 여부 추가 확인
            if privacy_line:
                restricted = run_shell(f"grep -E 'noexpn|novrfy|goaway' {config_file} 2>/dev/null").strip()
                check_results.append({
                    "sub_check": f"VRFY/EXPN 제한 옵션 확인 ({config_file})",
                    "config_file": config_file,
                    "collected_value": restricted if restricted else "noexpn/novrfy/goaway not found",
                    "raw_output": restricted if restricted else "NOT FOUND",
                    "service_status": "N/A",
                    "source_command": f"grep -E 'noexpn|novrfy|goaway' {config_file}"
                })

    # sendmail 서비스 실행 여부 확인 (참고용)
    sendmail_ps = run_shell("ps -ef | grep -E '[s]endmail' | grep -v grep")

    if sendmail_ps:
        service_status = "RUNNING"
        status_msg = "SMTP service is running"
    else:
        service_status = "NOT_RUNNING"
        status_msg = "SMTP service is not running (Safe)"

    # 종합 현황
    if not any(os.path.exists(f) for f in sendmail_files):
        summary = "No sendmail configuration file found"
    elif not privacy_options_found:
        summary = "PrivacyOptions not configured - VRFY/EXPN may be allowed"
    else:
        summary = "PrivacyOptions configured - Check for noexpn/novrfy/goaway"

    check_results.append({
        "sub_check": "expn, vrfy 명령어 제한 종합 현황",
        "config_file": "sendmail.cf",
        "collected_value": f"{summary} | Service: {service_status}",
        "raw_output": f"Sendmail Process:\n{sendmail_ps if sendmail_ps else 'No sendmail process'}",
        "service_status": service_status,
        "source_command": "ps -ef | grep sendmail && grep PrivacyOptions /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
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
                "item_code": "U-70",
                "item_name": "expn, vrfy 명령어 제한",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
