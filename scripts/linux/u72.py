#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-72 (하) 정책에 따른 시스템 로깅 설정 점검 스크립트
- syslog.conf 또는 rsyslog.conf 파일의 로깅 정책 설정 여부 및 내용 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u72_result_{scan_id}.json")


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
        print(f"[+] U-72 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    syslog_files = [
        "/etc/syslog.conf",
        "/etc/rsyslog.conf",
        "/etc/rsyslog.d/50-default.conf",
        "/etc/syslog-ng/syslog-ng.conf",
        "/etc/rsyslog.d/00-server.conf"
    ]

    found_any = False

    for config_file in syslog_files:
        if os.path.exists(config_file):
            found_any = True

            raw_content = run_shell(f"cat {config_file} 2>/dev/null")

            # 활성 로깅 규칙만 추출 (주석 제외 + 로그 관련 규칙)
            # 수정된 부분: '\\.' 으로 이스케이프 처리
            grep_cmd = f"grep -E '^[[:space:]]*[^#]' {config_file} 2>/dev/null | grep -E '\\.|/var/|/dev/' || true"
            active_lines = run_shell(grep_cmd)

            collected_value = active_lines.strip() if active_lines.strip() else "No active logging rules found"

            check_results.append({
                "sub_check": f"시스템 로깅 설정 ({config_file})",
                "config_file": config_file,
                "collected_value": collected_value,
                "raw_output": raw_content if raw_content else "NOT FOUND",
                "service_status": "N/A",
                "source_command": f"cat {config_file}"
            })

    if not found_any:
        check_results.append({
            "sub_check": "시스템 로깅 설정 파일 존재 여부",
            "config_file": "syslog.conf / rsyslog.conf",
            "collected_value": "No syslog configuration file found",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "ls -l /etc/syslog.conf /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null"
        })

    # syslog 데몬 실행 여부
    syslog_ps = run_shell("ps -ef | grep -E '[s]yslog[d]|[r]syslogd' | grep -v grep")

    check_results.append({
        "sub_check": "Syslog 데몬 실행 상태",
        "config_file": "syslog process",
        "collected_value": "Syslog daemon is RUNNING" if syslog_ps else "Syslog daemon is NOT RUNNING",
        "raw_output": syslog_ps if syslog_ps else "NOT FOUND",
        "service_status": "RUNNING" if syslog_ps else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[s]yslog[d]|[r]syslogd'"
    })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "로그 관리",
                "item_code": "U-72",
                "item_name": "정책에 따른 시스템 로깅 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
