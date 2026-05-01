#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-56 (중) UMASK 설정 관리 점검 스크립트
- 시스템 UMASK 값이 022 이상으로 설정되어 있는지 점검
- 주요 설정 파일: /etc/profile, /etc/default/login, /etc/default/security, /etc/security/user 등
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u56_result_{scan_id}.json")


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
        print(f"[+] U-56 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 주통기 기준 주요 설정 파일 목록
    config_files = [
        "/etc/profile",
        "/etc/default/login",
        "/etc/default/security",   # HP-UX
        "/etc/security/user",      # AIX
        "/root/.profile",
        "/etc/.profile"
    ]

    umask_found = False

    for config_file in config_files:
        if os.path.exists(config_file):
            # umask 또는 UMASK 값 추출 (대소문자 모두, umask 명령어와 변수 형태 모두)
            grep_cmd = f"grep -E '^[[:space:]]*(umask|UMASK)[[:space:]]*=' {config_file} 2>/dev/null || true"
            result = run_shell(grep_cmd).strip()

            # umask 명령어 형태도 추가 점검
            umask_cmd_form = f"grep -E '^[[:space:]]*umask[[:space:]]+[0-9]' {config_file} 2>/dev/null || true"
            umask_cmd_result = run_shell(umask_cmd_form).strip()

            raw_content = run_shell(f"cat {config_file} 2>/dev/null")

            if result or umask_cmd_result:
                collected = (result + "\n" + umask_cmd_result).strip()
                if collected:
                    check_results.append({
                        "sub_check": f"UMASK 설정 ({config_file})",
                        "config_file": config_file,
                        "collected_value": collected,
                        "raw_output": raw_content if raw_content else "NOT FOUND",
                        "service_status": "N/A",
                        "source_command": f"grep -E 'umask|UMASK' {config_file}"
                    })
                    umask_found = True

    # UMASK 설정이 전혀 발견되지 않은 경우
    if not umask_found:
        check_results.append({
            "sub_check": "UMASK 설정 전체 점검",
            "config_file": "/etc/profile 등",
            "collected_value": "No UMASK setting found",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "grep -E 'umask|UMASK' /etc/profile /etc/default/login /etc/default/security /etc/security/user 2>/dev/null || echo 'No UMASK found'"
        })

    # 현재 시스템의 umask 값도 함께 확인 (실제 적용 값)
    current_umask = run_shell("umask 2>/dev/null").strip()
    if current_umask:
        check_results.append({
            "sub_check": "현재 시스템 UMASK 값",
            "config_file": "umask command",
            "collected_value": current_umask,
            "raw_output": current_umask,
            "service_status": "N/A",
            "source_command": "umask"
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
                "item_code": "U-56",
                "item_name": "UMASK 설정 관리",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
