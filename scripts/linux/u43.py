#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-43 로그의 정기적 검토 및 보고 점검 스크립트
- 주요 보안 로그 파일 존재 여부 및 최근 내용 확인
- source_command: 실제 사용된 명령어를 그대로 저장
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u43_result_{scan_id}.json")


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
        print(f"[+] U-43 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    # 주요 보안 로그 파일 목록 (주통기에서 언급된 utmp, wtmp, btmp, sulog, xferlog 등)
    log_files = [
        "/var/log/wtmp",      # 로그인 성공 기록
        "/var/log/btmp",      # 로그인 실패 기록
        "/var/log/utmp",      # 현재 로그인 사용자
        "/var/log/lastlog",   # 마지막 로그인 정보
        "/var/log/auth.log",  # Ubuntu/Debian 인증 로그
        "/var/log/secure",    # RHEL/CentOS 인증 로그
        "/var/log/messages",  # 시스템 로그
        "/var/adm/sulog",     # su 명령어 로그 (Solaris 등)
        "/var/log/xferlog",   # FTP 로그
        "/var/log/secure.log"
    ]

    for log_path in log_files:
        if os.path.exists(log_path):
            # 파일 존재 + 최근 수정 시간 확인
            ls_cmd = f"ls -ld {log_path}"
            ls_raw = run_shell(ls_cmd)

            # 최근 로그 내용 일부 확인 (tail -n 10)
            tail_cmd = f"tail -n 10 {log_path} 2>/dev/null || echo '파일은 존재하나 읽기 권한 없음'"
            tail_raw = run_shell(tail_cmd)

            collected_value = f"파일 존재 | 크기: {os.path.getsize(log_path)} bytes" if tail_raw else "파일 존재"

            check_results.append({
                "sub_check": "보안 로그 파일",
                "config_file": log_path,
                "collected_value": collected_value,
                "raw_output": f"ls 결과:\n{ls_raw}\n\n최근 로그 미리보기:\n{tail_raw}",
                "service_status": "N/A",
                "source_command": f"ls -ld {log_path} && tail -n 10 {log_path}"
            })
        else:
            check_results.append({
                "sub_check": "보안 로그 파일",
                "config_file": log_path,
                "collected_value": "FILE NOT FOUND",
                "raw_output": "NOT FOUND",
                "service_status": "N/A",
                "source_command": f"ls -ld {log_path}"
            })

    # 추가: 로그 로테이션 설정 확인 (logrotate)
    if target_os == "linux":
        logrotate_cmd = "ls /etc/logrotate.d/ 2>/dev/null || echo 'logrotate 설정 없음'"
        logrotate_raw = run_shell(logrotate_cmd)
        
        check_results.append({
            "sub_check": "로그 로테이션 설정 (logrotate)",
            "config_file": "/etc/logrotate.d/",
            "collected_value": logrotate_raw if logrotate_raw else "NOT FOUND",
            "raw_output": logrotate_raw if logrotate_raw else "NOT FOUND",
            "service_status": "N/A",
            "source_command": "ls /etc/logrotate.d/"
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
                "item_code": "U-43",
                "item_name": "로그의 정기적 검토 및 보고",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
