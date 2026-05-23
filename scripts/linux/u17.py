#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-17 $HOME/.rhosts, hosts.equiv 사용 금지 점검 스크립트
- r-command 서비스 (rsh, rlogin, rexec 등) 실행 상태도 함께 확인
- 파일이 없어도 "파일 없음"으로 결과 기록
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u17_result_{scan_id}.json")


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


def check_service_status() -> str:
    """r-command 관련 서비스 상태 확인"""
    services = ["rsh", "rlogin", "rexec", "shell", "login", "rshell"]
    active_services = []

    for svc in services:
        # systemctl로 확인
        if run_shell(f"systemctl is-active {svc} 2>/dev/null") == "active":
            active_services.append(svc)
        # xinetd로 등록된 경우도 확인
        elif run_shell(f"grep -q '{svc}' /etc/xinetd.d/* 2>/dev/null") or run_shell(f"grep -q '{svc}' /etc/inetd.conf 2>/dev/null"):
            active_services.append(f"{svc} (xinetd/inetd)")

    if active_services:
        return f"RUNNING: {', '.join(active_services)}"
    return "NOT_RUNNING"


def save_json(result: Dict, output_dir: str, filename: str):
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] U-17 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    service_status = check_service_status()

    check_results: List[Dict[str, Any]] = []

    # 1. /etc/hosts.equiv 파일 점검
    equiv_path = "/etc/hosts.equiv"
    ls_result = run_shell(f"ls -al {equiv_path} 2>/dev/null")
    cat_result = run_shell(f"cat {equiv_path} 2>/dev/null") if os.path.exists(equiv_path) else ""

    check_results.append({
        "sub_check": "/etc/hosts.equiv 파일",
        "config_file": equiv_path,
        "collected_value": ls_result.splitlines()[0].strip() if ls_result else "파일 없음",
        "raw_output": f"Permission:\n{ls_result if ls_result else '파일 없음'}\n\nContent:\n{cat_result if cat_result else '파일 없음 또는 접근 불가'}",
        "service_status": service_status,
        "source_command": f"ls -al {equiv_path} && cat {equiv_path}"
    })

    # 2. root의 .rhosts 파일 점검
    root_rhosts = "/root/.rhosts"
    ls_result = run_shell(f"ls -al {root_rhosts} 2>/dev/null")
    cat_result = run_shell(f"cat {root_rhosts} 2>/dev/null") if os.path.exists(root_rhosts) else ""

    check_results.append({
        "sub_check": "/root/.rhosts 파일",
        "config_file": root_rhosts,
        "collected_value": ls_result.splitlines()[0].strip() if ls_result else "파일 없음",
        "raw_output": f"Permission:\n{ls_result if ls_result else '파일 없음'}\n\nContent:\n{cat_result if cat_result else '파일 없음 또는 접근 불가'}",
        "service_status": service_status,
        "source_command": f"ls -al {root_rhosts} && cat {root_rhosts}"
    })

    # 3. /home 내 사용자 .rhosts 파일 점검
    home_rhosts_found = False
    if os.path.exists("/home"):
        users = [u for u in run_shell("ls /home 2>/dev/null").split() if u]
        for user in users:
            rhosts_path = f"/home/{user}/.rhosts"
            if os.path.exists(rhosts_path):
                home_rhosts_found = True
                ls_result = run_shell(f"ls -al {rhosts_path}")
                cat_result = run_shell(f"cat {rhosts_path}")

                check_results.append({
                    "sub_check": f"/home/{user}/.rhosts 파일",
                    "config_file": rhosts_path,
                    "collected_value": ls_result.splitlines()[0].strip() if ls_result else "파일 없음",
                    "raw_output": f"Permission:\n{ls_result}\n\nContent:\n{cat_result}",
                    "service_status": service_status,
                    "source_command": f"ls -al {rhosts_path} && cat {rhosts_path}"
                })

    # .rhosts 파일이 하나도 없을 경우에도 결과 기록
    if not home_rhosts_found:
        check_results.append({
            "sub_check": "사용자 .rhosts 파일들",
            "config_file": "/home/*/.rhosts",
            "collected_value": "파일 없음",
            "raw_output": "모든 사용자 홈 디렉토리에 .rhosts 파일이 존재하지 않습니다.",
            "service_status": service_status,
            "source_command": "ls -al /home/*/.rhosts"
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
                "item_code": "U-17",
                "item_name": "$HOME/.rhosts, hosts.equiv 사용 금지",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
