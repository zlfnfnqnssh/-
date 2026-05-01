#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 점검 스크립트
- 홈 디렉토리 내 환경변수 파일(.profile, .bashrc 등) 점검
- collected_value에 실제 ls -l 결과 한 줄이 그대로 들어감
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u14_result_{scan_id}.json")


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
        print(f"[+] U-14 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== 점검할 환경변수 파일 목록 ====================
    env_files = [
        ".profile",
        ".bash_profile",
        ".bashrc",
        ".cshrc",
        ".kshrc",
        ".login",
        ".exrc",
        ".netrc"
    ]

    # root와 일반 사용자 홈 디렉토리 검사
    home_dirs = ["/root"]
    
    # /home 디렉토리 내 사용자 홈 디렉토리 추가
    if os.path.exists("/home"):
        home_users = run_shell("ls /home 2>/dev/null").split()
        for user in home_users:
            home_path = f"/home/{user}"
            if os.path.isdir(home_path):
                home_dirs.append(home_path)

    # ==================== 각 홈 디렉토리별 환경파일 점검 ====================
    for home_dir in home_dirs:
        for filename in env_files:
            full_path = os.path.join(home_dir, filename)
            
            if not os.path.exists(full_path):
                continue  # 파일이 없으면 스킵

            ls_result = run_shell(f"ls -l {full_path}")

            if ls_result:
                collected_value = ls_result.splitlines()[0].strip()
            else:
                collected_value = "파일 확인 실패"

            check_results.append({
                "sub_check": f"{home_dir}/{filename} 권한 및 소유자",
                "config_file": full_path,
                "collected_value": collected_value,        # 실제 ls -l 한 줄 그대로
                "raw_output": ls_result,
                "service_status": "N/A",
                "source_command": f"ls -l {full_path}"
            })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "파일 및 디렉토리 관리",        # "2." 삭제
                "item_code": "U-14",
                "item_name": "사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
