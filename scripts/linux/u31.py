#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-31 스팸 메일 릴레이 제한 점검 스크립트
- Sendmail 프로세스, sendmail.cf, access 파일, 그리고 "Relaying denied" 설정을 별도 항목으로 점검
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u31_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_os_info() -> tuple:
    """OS 정보 반환"""
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
    """JSON 파일로 저장"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] U-31 결과가 저장되었습니다: {filepath}")
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
        "sub_check": "Sendmail 서비스 실행 여부",
        "config_file": "프로세스",
        "collected_value": ps_result.splitlines()[0].strip() if ps_result else "FILE NOT FOUND",
        "raw_output": ps_result if ps_result else "Sendmail 프로세스가 실행 중이지 않습니다.",
        "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep sendmail | grep -v grep"
    })

    # 2. sendmail.cf 파일 확인 (전체)
    cf_paths = ["/etc/mail/sendmail.cf", "/etc/sendmail.cf"]
    for cf_path in cf_paths:
        if os.path.exists(cf_path):
            cat_result = run_shell(f"cat {cf_path}")
            check_results.append({
                "sub_check": "sendmail.cf 파일",
                "config_file": cf_path,
                "collected_value": cat_result.splitlines()[0].strip() if cat_result else "파일 내용 없음",
                "raw_output": cat_result,
                "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
                "source_command": f"cat {cf_path}"
            })

    # 3. Relaying denied 설정 확인 (사용자님이 요청한 명령어)
    relay_cmd = 'cat /etc/mail/sendmail.cf 2>/dev/null | grep "R$*" | grep "Relaying denied"'
    relay_result = run_shell(relay_cmd)

    check_results.append({
        "sub_check": "Relaying denied 설정 확인",
        "config_file": "/etc/mail/sendmail.cf",
        "collected_value": relay_result.strip() if relay_result else "FILE NOT FOUND 또는 설정 없음",
        "raw_output": relay_result if relay_result else "Relaying denied 설정을 찾을 수 없습니다.",
        "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
        "source_command": relay_cmd
    })

    # 4. /etc/mail/access 파일 확인
    access_path = "/etc/mail/access"
    if os.path.exists(access_path):
        access_result = run_shell(f"cat {access_path}")
        check_results.append({
            "sub_check": "Sendmail access 파일",
            "config_file": access_path,
            "collected_value": access_result.splitlines()[0].strip() if access_result else "파일 내용 없음",
            "raw_output": access_result,
            "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
            "source_command": f"cat {access_path}"
        })
    else:
        check_results.append({
            "sub_check": "Sendmail access 파일",
            "config_file": access_path,
            "collected_value": "FILE NOT FOUND",
            "raw_output": "access 파일이 존재하지 않습니다.",
            "service_status": "RUNNING" if ps_result else "NOT_RUNNING",
            "source_command": f"cat {access_path}"
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
                "item_code": "U-31",
                "item_name": "스팸 메일 릴레이 제한",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
