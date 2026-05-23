#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-66 (중) SNMP 서비스 구동 점검 스크립트
- SNMP 서비스(snmpd, snmpdx 등)가 실행 중인지 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u66_result_{scan_id}.json")


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
        print(f"[+] U-66 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # SNMP 관련 주요 프로세스 검색 (주통기와 동일하게 ps -ef | grep snmp 사용)
    snmp_ps_cmd = "ps -ef | grep -E '[s]nmpd|[s]nmpdx|dmisd|snmp' | grep -v grep"
    snmp_result = run_shell(snmp_ps_cmd)

    # 서비스 상태 판단
    service_status = "RUNNING" if snmp_result else "NOT_RUNNING"

    # 1. SNMP 서비스 실행 상태 (주요 점검)
    check_results.append({
        "sub_check": "SNMP 서비스 실행 상태",
        "config_file": "SNMP process",
        "collected_value": snmp_result if snmp_result else "No SNMP process",
        "raw_output": snmp_result if snmp_result else "NOT FOUND",
        "service_status": service_status,
        "source_command": "ps -ef | grep -E '[s]nmpd|[s]nmpdx|dmisd|snmp' | grep -v grep"
    })

    # 2. Solaris 전용 svcs 확인 (Solaris 10 이상)
    if target_os == "solaris":
        svcs_cmd = "svcs -a | grep -E 'snmp|dmi' 2>/dev/null || true"
        svcs_result = run_shell(svcs_cmd)
        
        if svcs_result:
            check_results.append({
                "sub_check": "Solaris SNMP 서비스 상태 (svcs)",
                "config_file": "svcs",
                "collected_value": svcs_result,
                "raw_output": svcs_result,
                "service_status": service_status,
                "source_command": "svcs -a | grep -E 'snmp|dmi'"
            })

    # 3. 종합 현황 (LLM 판단에 가장 중요한 항목)
    summary = f"SNMP Service Status: {service_status}"
    if snmp_result:
        summary += " (Risk: Information exposure possible)"

    check_results.append({
        "sub_check": "SNMP 서비스 구동 종합 현황",
        "config_file": "SNMP services",
        "collected_value": summary,
        "raw_output": f"Process List:\n{snmp_result if snmp_result else 'No SNMP-related processes found'}",
        "service_status": service_status,
        "source_command": "ps -ef | grep snmp && svcs -a | grep snmp 2>/dev/null"
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
                "item_code": "U-66",
                "item_name": "SNMP 서비스 구동 점검",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
