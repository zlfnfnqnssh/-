#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-11 /etc/syslog.conf 파일 소유자 및 권한 설정 점검 스크립트
- syslog.conf와 rsyslog.conf 모두 점검
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u11_result_{scan_id}.json")


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
        print(f"[+] U-11 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인 (rsyslog/syslog)
    _rsyslog_active = run_shell("systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null")
    _rsyslog_which  = run_shell("which rsyslogd syslogd 2>/dev/null | head -1")
    syslog_svc = "RUNNING" if _rsyslog_active.strip() == "active" else                  ("NOT_INSTALLED" if not _rsyslog_which else "NOT_RUNNING")


    # ==================== 점검 대상 파일 목록 ====================
    files_to_check = [
        ("/etc/syslog.conf", "ls -l /etc/syslog.conf"),
    ]

    # Linux의 경우 rsyslog.conf도 추가 점검
    if target_os == "linux":
        files_to_check.append(("/etc/rsyslog.conf", "ls -l /etc/rsyslog.conf"))

    # ==================== 파일 권한 점검 ====================
    for filepath, cmd in files_to_check:
        ls_result = run_shell(cmd)

        if ls_result:
            # 실제 ls -l 출력의 첫 번째 줄만 collected_value에 저장
            collected_value = ls_result.splitlines()[0].strip()
        else:
            collected_value = "파일 없음 또는 접근 불가"

        check_results.append({
            "sub_check": f"{filepath} 권한 및 소유자",
            "config_file": filepath,
            "collected_value": collected_value,        # 실제 ls -l 한 줄 그대로
            "raw_output": ls_result,
            "service_status": syslog_svc,
            "source_command": cmd
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
                "item_code": "U-11",
                "item_name": "/etc/syslog.conf 파일 소유자 및 권한 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
