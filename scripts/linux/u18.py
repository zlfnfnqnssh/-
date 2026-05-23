#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-18 접속 IP 및 포트 제한 점검 스크립트
- TCP Wrapper (hosts.allow, hosts.deny), iptables, inetd.sec 등 점검
- collected_value는 실제 내용의 핵심 라인만 저장
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u18_result_{scan_id}.json")


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
        print(f"[+] U-18 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== 1. TCP Wrapper 설정 점검 ====================
    # hosts.deny
    deny_path = "/etc/hosts.deny"
    if os.path.exists(deny_path):
        cat_result = run_shell(f"cat {deny_path}")
        check_results.append({
            "sub_check": "/etc/hosts.deny (TCP Wrapper)",
            "config_file": deny_path,
            "collected_value": cat_result.splitlines()[0].strip() if cat_result else "파일 내용 없음",
            "raw_output": cat_result,
            "service_status": "N/A",
            "source_command": f"cat {deny_path}"
        })
    else:
        check_results.append({
            "sub_check": "/etc/hosts.deny (TCP Wrapper)",
            "config_file": deny_path,
            "collected_value": "파일 없음",
            "raw_output": "파일이 존재하지 않습니다. (ALL:ALL 설정이 되어 있지 않을 수 있음)",
            "service_status": "N/A",
            "source_command": f"cat {deny_path}"
        })

    # hosts.allow
    allow_path = "/etc/hosts.allow"
    if os.path.exists(allow_path):
        cat_result = run_shell(f"cat {allow_path}")
        check_results.append({
            "sub_check": "/etc/hosts.allow (TCP Wrapper)",
            "config_file": allow_path,
            "collected_value": cat_result.splitlines()[0].strip() if cat_result else "파일 내용 없음",
            "raw_output": cat_result,
            "service_status": "N/A",
            "source_command": f"cat {allow_path}"
        })

    # ==================== 2. iptables (Linux) ====================
    if target_os == "linux":
        iptables_result = run_shell("iptables -L 2>/dev/null || iptables-save 2>/dev/null")
        check_results.append({
            "sub_check": "iptables 규칙",
            "config_file": "iptables",
            "collected_value": "설정 확인" if iptables_result else "iptables 규칙 없음",
            "raw_output": iptables_result if iptables_result else "iptables 규칙이 설정되어 있지 않습니다.",
            "service_status": "N/A",
            "source_command": "iptables -L"
        })

    # ==================== 3. HP-UX inetd.sec ====================
    if target_os == "hpux":
        inetd_sec_path = "/var/adm/inetd.sec"
        if os.path.exists(inetd_sec_path):
            cat_result = run_shell(f"cat {inetd_sec_path}")
            check_results.append({
                "sub_check": "/var/adm/inetd.sec (HP-UX)",
                "config_file": inetd_sec_path,
                "collected_value": cat_result.splitlines()[0].strip() if cat_result else "파일 내용 없음",
                "raw_output": cat_result,
                "service_status": "N/A",
                "source_command": f"cat {inetd_sec_path}"
            })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "파일 및 디렉토리 관리",
                "item_code": "U-18",
                "item_name": "접속 IP 및 포트 제한",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
