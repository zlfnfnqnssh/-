#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-48 패스워드 최소 사용기간 설정 점검 스크립트
- 패스워드 최소 사용기간 (1일 이상) 설정 확인
- collected_value: 핵심 설정 값만 추출
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u48_result_{scan_id}.json")


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
        print(f"[+] U-48 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    if target_os == "linux":
        # Linux: /etc/login.defs - PASS_MIN_DAYS
        file_path = "/etc/login.defs"
        if os.path.exists(file_path):
            raw = run_shell(f"cat {file_path}")
            grep_cmd = f"grep -E '^PASS_MIN_DAYS' {file_path}"
            
            match = re.search(r'PASS_MIN_DAYS\s+(\d+)', raw, re.IGNORECASE)
            collected = match.group(0).strip() if match else "PASS_MIN_DAYS 설정 없음"

            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (Linux)",
                "config_file": file_path,
                "collected_value": collected,
                "raw_output": raw,
                "service_status": "N/A",
                "source_command": grep_cmd
            })
        else:
            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (Linux)",
                "config_file": "/etc/login.defs",
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": "N/A",
                "source_command": "grep '^PASS_MIN_DAYS' /etc/login.defs"
            })

    elif target_os == "solaris":
        # Solaris: /etc/default/passwd - MINWEEKS
        file_path = "/etc/default/passwd"
        if os.path.exists(file_path):
            raw = run_shell(f"cat {file_path}")
            grep_cmd = f"grep -E '^MINWEEKS' {file_path}"

            match = re.search(r'MINWEEKS\s*=\s*(\d+)', raw, re.IGNORECASE)
            collected = match.group(0).strip() if match else "MINWEEKS 설정 없음"

            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (Solaris)",
                "config_file": file_path,
                "collected_value": collected,
                "raw_output": raw,
                "service_status": "N/A",
                "source_command": grep_cmd
            })
        else:
            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (Solaris)",
                "config_file": "/etc/default/passwd",
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": "N/A",
                "source_command": "grep '^MINWEEKS' /etc/default/passwd"
            })

    elif target_os == "aix":
        # AIX: /etc/security/user - minage
        file_path = "/etc/security/user"
        if os.path.exists(file_path):
            raw = run_shell(f"cat {file_path}")
            grep_cmd = "grep -E 'minage' /etc/security/user"

            match = re.search(r'minage\s*=\s*(\d+)', raw, re.IGNORECASE)
            collected = match.group(0).strip() if match else "minage 설정 없음"

            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (AIX)",
                "config_file": file_path,
                "collected_value": collected,
                "raw_output": raw,
                "service_status": "N/A",
                "source_command": grep_cmd
            })
        else:
            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (AIX)",
                "config_file": "/etc/security/user",
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": "N/A",
                "source_command": "grep 'minage' /etc/security/user"
            })

    elif target_os == "hpux":
        # HP-UX: /etc/default/security - PASSWORD_MINDAYS
        file_path = "/etc/default/security"
        if os.path.exists(file_path):
            raw = run_shell(f"cat {file_path}")
            grep_cmd = f"grep -E 'PASSWORD_MINDAYS' {file_path}"

            match = re.search(r'PASSWORD_MINDAYS\s*=\s*(\d+)', raw, re.IGNORECASE)
            collected = match.group(0).strip() if match else "PASSWORD_MINDAYS 설정 없음"

            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (HP-UX)",
                "config_file": file_path,
                "collected_value": collected,
                "raw_output": raw,
                "service_status": "N/A",
                "source_command": grep_cmd
            })
        else:
            check_results.append({
                "sub_check": "패스워드 최소 사용기간 (HP-UX)",
                "config_file": "/etc/default/security",
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": "N/A",
                "source_command": "grep 'PASSWORD_MINDAYS' /etc/default/security"
            })

    else:
        check_results.append({
            "sub_check": "패스워드 최소 사용기간",
            "config_file": "OS별 설정 파일",
            "collected_value": "지원되지 않는 OS",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "uname -a"
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
                "item_code": "U-48",
                "item_name": "패스워드 최소 사용기간 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
