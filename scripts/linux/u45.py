#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-45 root 계정 su 제한 점검 스크립트
- wheel 그룹 멤버 + su 바이너리 권한 + PAM 설정 확인
- collected_value: 핵심 판단 정보 요약
"""
import subprocess
import json
import os
import platform
import re
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u45_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
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
        print(f"[+] U-45 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    # 1. wheel 그룹 및 멤버 확인
    group_cmd = "grep '^wheel:' /etc/group || echo 'wheel 그룹 없음'"
    group_raw = run_shell(group_cmd)
    collected_group = group_raw.strip()

    check_results.append({
        "sub_check": "wheel 그룹 및 멤버",
        "config_file": "/etc/group",
        "collected_value": collected_group,
        "raw_output": group_raw,
        "service_status": "N/A",
        "source_command": "grep '^wheel:' /etc/group"
    })

    # 2. su 바이너리 위치 찾기 및 권한 확인
    su_paths = ["/usr/bin/su", "/bin/su"]
    su_found = False
    for su_path in su_paths:
        if os.path.exists(su_path):
            su_found = True
            ls_cmd = f"ls -l {su_path}"
            ls_raw = run_shell(ls_cmd)

            # 권한과 소유 그룹 추출 (예: -rwsr-x--- 1 root wheel ...)
            perm_match = re.search(r'^(.{10})\s+\d+\s+\S+\s+(\S+)', ls_raw)
            permission = perm_match.group(1) if perm_match else "UNKNOWN"
            group = perm_match.group(2) if perm_match else "UNKNOWN"

            collected_su = f"경로: {su_path} | 권한: {permission} | 그룹: {group}"

            check_results.append({
                "sub_check": "su 명령어 파일 권한",
                "config_file": su_path,
                "collected_value": collected_su,
                "raw_output": ls_raw,
                "service_status": "N/A",
                "source_command": ls_cmd
            })
            break

    if not su_found:
        check_results.append({
            "sub_check": "su 명령어 파일 권한",
            "config_file": "/usr/bin/su",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "ls -l /usr/bin/su"
        })

    # 3. Linux PAM 설정 확인 (/etc/pam.d/su)
    if target_os == "linux":
        pam_file = "/etc/pam.d/su"
        if os.path.exists(pam_file):
            pam_raw = run_shell(f"cat {pam_file}")
            # pam_wheel 관련 라인만 추출
            pam_wheel_lines = re.findall(r'.*pam_wheel\.so.*', pam_raw, re.IGNORECASE)
            collected_pam = "\n".join(pam_wheel_lines) if pam_wheel_lines else "pam_wheel 설정 없음"

            check_results.append({
                "sub_check": "PAM su 설정 (pam_wheel)",
                "config_file": pam_file,
                "collected_value": collected_pam,
                "raw_output": pam_raw,
                "service_status": "N/A",
                "source_command": f"grep 'pam_wheel' {pam_file}"
            })
        else:
            check_results.append({
                "sub_check": "PAM su 설정 (pam_wheel)",
                "config_file": pam_file,
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": "N/A",
                "source_command": "cat /etc/pam.d/su"
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
                "item_code": "U-45",
                "item_name": "root 계정 su 제한",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
