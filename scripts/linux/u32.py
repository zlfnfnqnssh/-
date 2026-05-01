#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-32 일반사용자의 Sendmail 실행 방지 점검 스크립트
- Sendmail 프로세스와 PrivacyOptions(restrictqrun) 설정 점검
- raw_output: 파일이 있으면 전체 내용, 없으면 "NOT FOUND"
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u32_result_{scan_id}.json")


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
        print(f"[+] U-32 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 1. Sendmail 프로세스 확인
    ps_result = run_shell("ps -ef | grep sendmail | grep -v grep")

    check_results.append({
        "sub_check": "Sendmail 프로세스",
        "config_file": "프로세스",
        "collected_value": ps_result.splitlines()[0].strip() if ps_result else "FILE NOT FOUND",
        "raw_output": ps_result if ps_result else "NOT FOUND",
        "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep sendmail | grep -v grep"
    })

    # 2. sendmail.cf PrivacyOptions 확인
    cf_paths = ["/etc/mail/sendmail.cf", "/etc/sendmail.cf"]

    for cf_path in cf_paths:
        if os.path.exists(cf_path):
            # PrivacyOptions 라인 추출
            privacy_cmd = f"grep -v '^ *#' {cf_path} | grep -i PrivacyOptions"
            privacy_result = run_shell(privacy_cmd)

            collected = privacy_result.strip() if privacy_result else "PrivacyOptions 설정 없음"

            check_results.append({
                "sub_check": "Sendmail PrivacyOptions",
                "config_file": cf_path,
                "collected_value": collected,
                "raw_output": privacy_result if privacy_result else "NOT FOUND",
                "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
                "source_command": privacy_cmd
            })
        else:
            check_results.append({
                "sub_check": "Sendmail PrivacyOptions",
                "config_file": cf_path,
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
                "source_command": f"grep -i PrivacyOptions {cf_path}"
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
                "item_code": "U-32",
                "item_name": "일반사용자의 Sendmail 실행 방지",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
