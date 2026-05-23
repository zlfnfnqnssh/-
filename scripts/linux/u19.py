#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-19 Finger 서비스 비활성화 점검 스크립트
- collected_value는 핵심 문구 한 줄만 저장
- 파일 없음 → "FILE NOT FOUND"
- 서비스 상태 명확히 표시
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u19_result_{scan_id}.json")


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


def check_finger_service_status() -> str:
    """Finger 서비스 실행 상태 확인"""
    # xinetd 방식
    if os.path.exists("/etc/xinetd.d/finger"):
        content = run_shell("cat /etc/xinetd.d/finger 2>/dev/null")
        if content and "disable = no" in content.lower():
            return "RUNNING (xinetd)"
        else:
            return "INSTALLED (disabled)"

    # inetd.conf 방식
    inetd_line = run_shell("grep -i finger /etc/inetd.conf 2>/dev/null")
    if inetd_line and not inetd_line.strip().startswith("#"):
        return "RUNNING (inetd)"

    # systemctl 방식
    if run_shell("systemctl is-active finger 2>/dev/null") == "active":
        return "RUNNING (systemd)"

    return "NOT_RUNNING"


def save_json(result: Dict, output_dir: str, filename: str):
    """JSON 파일로 저장"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] U-19 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []
    service_status = check_finger_service_status()

    # ==================== Finger 서비스 설정 파일 점검 ====================

    # 1. /etc/inetd.conf
    inetd_line = run_shell("grep -i finger /etc/inetd.conf 2>/dev/null")
    collected_inetd = inetd_line.strip() if inetd_line else "FILE NOT FOUND"

    check_results.append({
        "sub_check": "Finger 서비스 (inetd.conf)",
        "config_file": "/etc/inetd.conf",
        "collected_value": collected_inetd,
        "raw_output": inetd_line if inetd_line else "Finger 관련 설정 없음",
        "service_status": service_status,
        "source_command": "grep -i finger /etc/inetd.conf"
    })

    # 2. /etc/xinetd.d/finger (Linux)
    if target_os == "linux":
        xinetd_path = "/etc/xinetd.d/finger"
        if os.path.exists(xinetd_path):
            cat_result = run_shell(f"cat {xinetd_path}")
            collected_xinetd = cat_result.splitlines()[0].strip() if cat_result else "파일 내용 없음"
        else:
            collected_xinetd = "FILE NOT FOUND"
            cat_result = "파일 없음"

        check_results.append({
            "sub_check": "Finger 서비스 (xinetd)",
            "config_file": "/etc/xinetd.d/finger",
            "collected_value": collected_xinetd,
            "raw_output": cat_result,
            "service_status": service_status,
            "source_command": "cat /etc/xinetd.d/finger"
        })

    # 3. Solaris inetadm 방식
    if target_os == "solaris":
        inetadm_result = run_shell("inetadm | grep -i finger 2>/dev/null")
        collected = inetadm_result.strip() if inetadm_result else "FILE NOT FOUND"

        check_results.append({
            "sub_check": "Finger 서비스 (inetadm)",
            "config_file": "inetadm",
            "collected_value": collected,
            "raw_output": inetadm_result if inetadm_result else "Finger 서비스 미등록",
            "service_status": service_status,
            "source_command": "inetadm | grep finger"
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
                "item_code": "U-19",
                "item_name": "Finger 서비스 비활성화",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
