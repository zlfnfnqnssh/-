#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-53 (하) 사용자 shell 점검 스크립트
- 로그인이 불필요한 시스템 계정에 쉘(/bin/false 또는 /sbin/nologin)이 부여되었는지 점검
- 주통기에서 제시한 egrep 명령어를 최대한 동일하게 사용
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u53_result_{scan_id}.json")


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
        print(f"[+] U-53 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    passwd_file = "/etc/passwd"

    if os.path.exists(passwd_file):
        # 주통기와 최대한 동일한 명령어 사용
        check_cmd = r"""cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v "admin" """

        raw_output = run_shell(check_cmd)

        # collected_value: 로그인 불필요 계정 중 쉘이 /bin/false 또는 /sbin/nologin이 아닌 계정만 추출 (판단 핵심)
        if raw_output:
            collect_cmd = r"""
cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v "admin" | \
awk -F: '$7 !~ /false|nologin/ {print $1 ":" $7}'
"""
            collected_value = run_shell(collect_cmd).strip()
            if not collected_value:
                collected_value = "All system accounts have restricted shell"
        else:
            collected_value = "No target system accounts found"

        check_results.append({
            "sub_check": "로그인 불필요 계정 Shell 점검",
            "config_file": "/etc/passwd",
            "collected_value": collected_value,
            "raw_output": raw_output if raw_output else "NOT FOUND",
            "service_status": "N/A",
            "source_command": check_cmd.strip()
        })

        # 전체 대상 계정 목록 (참고용)
        if raw_output:
            check_results.append({
                "sub_check": "대상 시스템 계정 전체 목록",
                "config_file": "/etc/passwd",
                "collected_value": raw_output,
                "raw_output": raw_output,
                "service_status": "N/A",
                "source_command": check_cmd.strip()
            })
    else:
        check_results.append({
            "sub_check": "로그인 불필요 계정 Shell 점검",
            "config_file": "/etc/passwd",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "cat /etc/passwd | egrep ..."
        })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "계정관리",
                "item_code": "U-53",
                "item_name": "사용자 shell 점검",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
