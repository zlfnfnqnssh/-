#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-26 automountd 제거 점검 스크립트
- automountd / autofs 서비스 실행 여부 점검
- collected_value는 핵심 한 줄만 저장
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u26_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
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
        print(f"[+] U-26 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== automountd / autofs 서비스 점검 ====================

    # 1. 프로세스 확인 (모든 OS 공통)
    ps_result = run_shell("ps -ef | grep -E 'automount|autofs' | grep -v grep")

    if ps_result:
        collected_ps = ps_result.splitlines()[0].strip()
        service_status = "RUNNING"
    else:
        collected_ps = "FILE NOT FOUND"
        service_status = "NOT_RUNNING"

    check_results.append({
        "sub_check": "automountd / autofs 프로세스",
        "config_file": "프로세스",
        "collected_value": collected_ps,
        "raw_output": ps_result if ps_result else "automountd/autofs 프로세스가 실행 중이지 않습니다.",
        "service_status": service_status,
        "source_command": "ps -ef | grep -E 'automount|autofs' | grep -v grep"
    })

    # 2. Linux - systemd 서비스 확인
    if target_os == "linux":
        autofs_status = run_shell("systemctl is-active autofs 2>/dev/null")
        if autofs_status:
            check_results.append({
                "sub_check": "autofs 서비스 (systemd)",
                "config_file": "systemctl",
                "collected_value": f"autofs: {autofs_status}",
                "raw_output": autofs_status,
                "service_status": "RUNNING" if autofs_status == "active" else "NOT_RUNNING",
                "source_command": "systemctl is-active autofs"
            })

    # 3. Solaris inetadm / svcs 방식
    if target_os == "solaris":
        svcs_result = run_shell("svcs -a | grep -E 'autofs|automount' 2>/dev/null")
        if svcs_result:
            check_results.append({
                "sub_check": "autofs 서비스 (Solaris)",
                "config_file": "svcs",
                "collected_value": svcs_result.splitlines()[0].strip(),
                "raw_output": svcs_result,
                "service_status": "RUNNING",
                "source_command": "svcs -a | grep -E 'autofs|automount'"
            })

    # automount 관련 서비스가 전혀 없을 경우
    if len([item for item in check_results if "FILE NOT FOUND" not in item["collected_value"]]) == 0:
        check_results.append({
            "sub_check": "automountd / autofs 전체",
            "config_file": "automount 관련 서비스",
            "collected_value": "FILE NOT FOUND 또는 비활성화",
            "raw_output": "automountd 또는 autofs 서비스가 실행 중이거나 설정되어 있지 않습니다.",
            "service_status": "NOT_RUNNING",
            "source_command": "ps -ef | grep -E 'automount|autofs' | grep -v grep && svcs -a | grep autofs"
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
                "item_code": "U-26",
                "item_name": "automountd 제거",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
