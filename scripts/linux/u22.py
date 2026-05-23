#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-22 crond 파일 소유자 및 권한 설정 점검 스크립트
- crontab 명령어 및 cron 관련 파일/디렉토리 권한 점검
- /var/spool/cron/ 과 /var/spool/cron/crontabs/ 를 OS 공통으로 항상 점검
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u22_result_{scan_id}.json")


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
        print(f"[+] U-22 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인
    _svc_active = run_shell("systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null")
    cron_svc = "RUNNING" if _svc_active.strip() == "active" else \
               ("NOT_INSTALLED" if not run_shell("which cron crond 2>/dev/null | head -1") else "NOT_RUNNING")


    # ==================== 주요 cron 관련 파일 및 디렉토리 ====================
    cron_items = [
        "/usr/bin/crontab",
        "/etc/cron.allow",
        "/etc/cron.deny",
        "/etc/crontab",
        "/var/spool/cron",           # OS 공통
        "/var/spool/cron/crontabs",  # OS 공통
    ]

    # OS별 추가 파일/디렉토리
    if target_os == "linux":
        cron_items.extend([
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ])
    elif target_os in ["solaris", "aix", "hpux"]:
        cron_items.extend([
            "/etc/cron.d",
            "/var/adm/cron",
        ])

    # ==================== 권한 점검 ====================
    for path in cron_items:
        if not os.path.exists(path):
            check_results.append({
                "sub_check": f"{path} 권한 및 소유자",
                "config_file": path,
                "collected_value": "FILE NOT FOUND",
                "raw_output": "파일 또는 디렉토리가 존재하지 않습니다.",
                "service_status": cron_svc,
                "source_command": f"ls -ld {path}"
            })
            continue

        # 디렉토리면 ls -ld, 파일이면 ls -l 사용
        if os.path.isdir(path):
            ls_result = run_shell(f"ls -ld {path}")
        else:
            ls_result = run_shell(f"ls -l {path}")

        collected_value = ls_result.splitlines()[0].strip() if ls_result else "권한 확인 실패"

        check_results.append({
            "sub_check": f"{path} 권한 및 소유자",
            "config_file": path,
            "collected_value": collected_value,
            "raw_output": ls_result,
            "service_status": cron_svc,
            "source_command": f"ls -l{'d' if os.path.isdir(path) else ''} {path}"
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
                "item_code": "U-22",
                "item_name": "crond 파일 소유자 및 권한 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
