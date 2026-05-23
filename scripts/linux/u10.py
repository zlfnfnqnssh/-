#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-10 /etc/(x)inetd.conf 파일 소유자 및 권한 설정 점검 스크립트
- /etc/xinetd.d/* 의 ls -al 결과도 별도의 item으로 추가
- collected_value에는 실제 ls 결과 한 줄이 그대로 들어감
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u10_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
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
        print(f"[+] U-10 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인 (xinetd/inetd)
    _xinetd_active = run_shell("systemctl is-active xinetd 2>/dev/null || systemctl is-active inetd 2>/dev/null")
    _xinetd_which  = run_shell("which xinetd inetd 2>/dev/null | head -1")
    inetd_svc = "RUNNING" if _xinetd_active.strip() == "active" else                 ("NOT_INSTALLED" if not _xinetd_which else "NOT_RUNNING")


    # ==================== 1. inetd.conf 점검 ====================
    ls_inetd = run_shell("ls -l /etc/inetd.conf 2>/dev/null")
    if ls_inetd:
        collected_inetd = ls_inetd.splitlines()[0].strip()
    else:
        collected_inetd = "파일 없음"

    check_results.append({
        "sub_check": "/etc/inetd.conf 권한 및 소유자",
        "config_file": "/etc/inetd.conf",
        "collected_value": collected_inetd,
        "raw_output": ls_inetd,
        "service_status": inetd_svc,
        "source_command": "ls -l /etc/inetd.conf"
    })

    # ==================== 2. xinetd.conf 점검 ====================
    ls_xinetd = run_shell("ls -l /etc/xinetd.conf 2>/dev/null")
    if ls_xinetd:
        collected_xinetd = ls_xinetd.splitlines()[0].strip()
    else:
        collected_xinetd = "파일 없음"

    check_results.append({
        "sub_check": "/etc/xinetd.conf 권한 및 소유자",
        "config_file": "/etc/xinetd.conf",
        "collected_value": collected_xinetd,
        "raw_output": ls_xinetd,
        "service_status": inetd_svc,
        "source_command": "ls -l /etc/xinetd.conf"
    })

    # ==================== 3. /etc/xinetd.d/* 디렉토리 내 모든 파일 점검 (별도 item) ====================
    ls_xinetd_d = run_shell("ls -al /etc/xinetd.d/* 2>/dev/null")

    if ls_xinetd_d:
        # collected_value에는 첫 번째 줄만 (너무 길지 않게)
        first_line = ls_xinetd_d.splitlines()[0].strip() if ls_xinetd_d.splitlines() else "파일 없음"
        collected_d = first_line
    else:
        collected_d = "디렉토리 없음 또는 파일 없음"

    check_results.append({
        "sub_check": "/etc/xinetd.d/ 디렉토리 파일들",
        "config_file": "/etc/xinetd.d/",
        "collected_value": collected_d,                    # 첫 번째 줄만
        "raw_output": ls_xinetd_d,                         # 전체 결과
        "service_status": inetd_svc,
        "source_command": "ls -al /etc/xinetd.d/*"
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
                "item_code": "U-10",
                "item_name": "/etc/(x)inetd.conf 파일 소유자 및 권한 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
