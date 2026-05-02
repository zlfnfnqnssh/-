#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-23 DoS 공격에 취약한 서비스 비활성화 점검 스크립트
- raw_output은 실제 명령어 실행 결과 그대로 저장
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u23_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
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
        print(f"[+] U-23 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    vulnerable_services = ["echo", "discard", "daytime", "chargen"]

    # ==================== 1. inetd.conf 방식 ====================
    inetd_cmd = f"grep -E '{'|'.join(vulnerable_services)}' /etc/inetd.conf 2>/dev/null"
    inetd_result = run_shell(inetd_cmd)

    check_results.append({
        "sub_check": "DoS 취약 서비스 (inetd.conf)",
        "config_file": "/etc/inetd.conf",
        "collected_value": inetd_result.strip() if inetd_result else "FILE NOT FOUND",
        "raw_output": inetd_result if inetd_result else "",   # 실제 grep 결과 그대로
        "service_status": "RUNNING" if inetd_result and not inetd_result.strip().startswith("#") else "NOT_RUNNING",
        "source_command": inetd_cmd
    })

    # ==================== 2. xinetd 방식 (Linux) ====================
    if target_os == "linux":
        for svc in vulnerable_services:
            path = f"/etc/xinetd.d/{svc}"
            if os.path.exists(path):
                cat_result = run_shell(f"cat {path}")
                collected = cat_result.splitlines()[0].strip() if cat_result else "파일 내용 없음"

                check_results.append({
                    "sub_check": f"DoS 취약 서비스 (xinetd/{svc})",
                    "config_file": path,
                    "collected_value": collected,
                    "raw_output": cat_result,                    # 실제 cat 결과 그대로
                    "service_status": "INSTALLED",
                    "source_command": f"cat {path}"
                })
            else:
                check_results.append({
                    "sub_check": f"DoS 취약 서비스 (xinetd/{svc})",
                    "config_file": path,
                    "collected_value": "FILE NOT FOUND",
                    "raw_output": "",                            # 빈 문자열로 실제 결과처럼
                    "service_status": "NOT_RUNNING",
                    "source_command": f"cat {path}"
                })

    # ==================== 3. Solaris inetadm 방식 ====================
    if target_os == "solaris":
        for svc in vulnerable_services:
            inetadm_cmd = f"inetadm | grep -i {svc} 2>/dev/null"
            inetadm_result = run_shell(inetadm_cmd)

            check_results.append({
                "sub_check": f"DoS 취약 서비스 (inetadm/{svc})",
                "config_file": "inetadm",
                "collected_value": inetadm_result.strip() if inetadm_result else "FILE NOT FOUND",
                "raw_output": inetadm_result,                   # 실제 결과 그대로
                "service_status": "RUNNING" if inetadm_result else "NOT_RUNNING",
                "source_command": inetadm_cmd
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
                "item_code": "U-23",
                "item_name": "DoS 공격에 취약한 서비스 비활성화",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
