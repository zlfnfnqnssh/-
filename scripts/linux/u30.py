#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-30 Sendmail 버전 점검 스크립트
- Sendmail 서비스 실행 여부 및 버전 확인
- collected_value는 실제 버전 정보 한 줄만 저장
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u30_result_{scan_id}.json")


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
        print(f"[+] U-30 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== 1. Sendmail 프로세스 확인 ====================
    ps_result = run_shell("ps -ef | grep sendmail | grep -v grep")

    if ps_result:
        collected_ps = ps_result.splitlines()[0].strip()
        service_status = "RUNNING"
    else:
        collected_ps = "FILE NOT FOUND"
        service_status = "NOT_RUNNING"

    check_results.append({
        "sub_check": "Sendmail 프로세스",
        "config_file": "프로세스",
        "collected_value": collected_ps,
        "raw_output": ps_result if ps_result else "Sendmail 프로세스가 실행 중이지 않습니다.",
        "service_status": service_status,
        "source_command": "ps -ef | grep sendmail | grep -v grep"
    })

    # ==================== 2. Sendmail 버전 확인 ====================
    # telnet localhost 25로 버전 확인 시도
    version_cmd = "echo 'QUIT' | telnet localhost 25 2>/dev/null | grep -i 'sendmail' || echo 'VERSION CHECK FAILED'"
    version_result = run_shell(version_cmd)

    if "sendmail" in version_result.lower():
        collected_version = version_result.strip()
    else:
        # sendmail 명령어로 버전 확인 시도
        version_result = run_shell("sendmail -d0.1 -bt < /dev/null 2>&1 | head -5")
        collected_version = version_result.strip() if version_result else "VERSION CHECK FAILED"

    check_results.append({
        "sub_check": "Sendmail 버전",
        "config_file": "sendmail",
        "collected_value": collected_version,
        "raw_output": version_result,
        "service_status": service_status,
        "source_command": "echo 'QUIT' | telnet localhost 25 && sendmail -d0.1 -bt"
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
                "item_code": "U-30",
                "item_name": "Sendmail 버전 점검",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
