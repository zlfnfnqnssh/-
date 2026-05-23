#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-67 (중) SNMP 서비스 Community String 복잡성 설정 점검 스크립트
- SNMP Community String이 default 값(public, private)을 사용하고 있는지 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u67_result_{scan_id}.json")


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
        print(f"[+] U-67 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== OS별 SNMP 설정 파일 목록 ====================
    snmp_config_files = [
        # Solaris
        "/etc/snmp/conf/snmpd.conf",
        "/etc/sma/snmp/snmpd.conf",
        # Linux
        "/etc/snmp/snmpd.conf",
        "/etc/snmpd.conf",
        # AIX
        "/etc/snmpdv3.conf",
        "/etc/snmpd.conf",
        # HP-UX
        "/etc/snmpd.conf",
        "/var/adm/snmpd.conf"
    ]

    default_community_found = False
    dangerous_patterns = ["public", "private"]

    for config_file in snmp_config_files:
        if os.path.exists(config_file):
            raw_content = run_shell(f"cat {config_file} 2>/dev/null")

            # public 또는 private 문자열 검색 (대소문자 구분 없이)
            found_lines = []
            for pattern in dangerous_patterns:
                cmd = f"grep -i '{pattern}' {config_file} 2>/dev/null || true"
                result = run_shell(cmd)
                if result:
                    found_lines.append(result)

            collected_value = "\n".join(found_lines) if found_lines else "No default community (public/private) found"

            if found_lines:
                default_community_found = True

            check_results.append({
                "sub_check": f"SNMP Community String 점검 ({config_file})",
                "config_file": config_file,
                "collected_value": collected_value,
                "raw_output": raw_content if raw_content else "NOT FOUND",
                "service_status": "N/A",
                "source_command": f"cat {config_file} | grep -iE 'public|private'"
            })

    # SNMP 서비스가 실행 중인지 확인 (참고용)
    snmp_ps = run_shell("ps -ef | grep -E '[s]nmpd|[s]nmpdx|dmisd' | grep -v grep")

    if snmp_ps:
        service_status = "RUNNING"
    else:
        service_status = "NOT_RUNNING"

    # 종합 현황
    if not any(os.path.exists(f) for f in snmp_config_files):
        summary_collected = "No SNMP configuration file found"
    elif default_community_found:
        summary_collected = "Default Community String (public/private) detected - Vulnerable"
    else:
        summary_collected = "No default Community String found - Good"

    check_results.append({
        "sub_check": "SNMP Community String 종합 현황",
        "config_file": "SNMP config files",
        "collected_value": summary_collected,
        "raw_output": f"SNMP Process:\n{snmp_ps if snmp_ps else 'No SNMP process'}",
        "service_status": service_status,
        "source_command": "ps -ef | grep snmp && grep -iE 'public|private' /etc/*/snmp* /etc/snmp* /var/adm/snmp* 2>/dev/null"
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
                "item_code": "U-67",
                "item_name": "SNMP 서비스 Community String의 복잡성 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
