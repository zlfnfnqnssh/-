#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-54 (하) Session Timeout 설정 점검 스크립트
- /etc/profile, .profile, /etc/csh.login, /etc/csh.cshrc 파일에서 TMOUT 또는 autologout 설정 확인
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u54_result_{scan_id}.json")


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
        print(f"[+] U-54 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 점검 대상 파일 목록 (주통기 기준)
    files_to_check = [
        "/etc/profile",
        "/etc/.profile",      # 일부 시스템에서 사용
        "/root/.profile",
        "/etc/csh.login",
        "/etc/csh.cshrc"
    ]

    found_settings = []

    for config_file in files_to_check:
        if os.path.exists(config_file):
            # TMOUT 설정 추출 (sh/ksh/bash 계열)
            tmout_cmd = f"grep -E 'TMOUT=' {config_file} 2>/dev/null || true"
            tmout_result = run_shell(tmout_cmd).strip()

            # autologout 설정 추출 (csh 계열)
            autologout_cmd = f"grep -E 'set autologout=' {config_file} 2>/dev/null || true"
            autologout_result = run_shell(autologout_cmd).strip()

            raw_content = run_shell(f"cat {config_file} 2>/dev/null")

            if tmout_result or autologout_result:
                collected = ""
                if tmout_result:
                    collected += tmout_result + "\n"
                if autologout_result:
                    collected += autologout_result

                check_results.append({
                    "sub_check": f"Session Timeout 설정 ({config_file})",
                    "config_file": config_file,
                    "collected_value": collected.strip(),
                    "raw_output": raw_content if raw_content else "NOT FOUND",
                    "service_status": "N/A",
                    "source_command": f"grep -E 'TMOUT=|set autologout=' {config_file}"
                })

                found_settings.append(f"{config_file}: {collected.strip()}")

    # 전체 파일 중 설정이 하나도 없는 경우 명확히 표시
    if not found_settings:
        # 대표 파일 점검 결과 추가
        check_results.append({
            "sub_check": "Session Timeout 설정 전체",
            "config_file": "/etc/profile, /etc/csh.login 등",
            "collected_value": "No TMOUT or autologout setting found",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "grep -E 'TMOUT=|set autologout=' /etc/profile /etc/csh.login /etc/csh.cshrc 2>/dev/null || echo 'No setting found'"
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
                "item_code": "U-54",
                "item_name": "Session Timeout 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
