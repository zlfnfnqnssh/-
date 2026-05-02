#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-64 (중) FTP 서비스 root 계정 접근제한 점검 스크립트
- FTP 서비스에서 root 계정 직접 접속이 차단되어 있는지 점검
- 각 ftpusers 파일별 상세 점검 + FTP 서비스 실행 상태 반영
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u64_result_{scan_id}.json")


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
        print(f"[+] U-64 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== 점검 대상 파일 목록 ====================
    ftp_files = [
        "/etc/ftpusers",
        "/etc/ftpd/ftpusers",
        "/etc/vsftp/ftpusers",
        "/etc/vsftp/user_list",
        "/etc/vsftpd/ftpusers",
        "/etc/vsftpd/user_list",
        "/etc/vsftpd.ftpusers",
        "/etc/vsftpd.user_list",
        "/etc/vsftpd/vsftpd.ftpusers",
        "/etc/proftpd.conf",
        "/etc/proftpd/proftpd.conf"
    ]

    # FTP 서비스 실행 여부 확인 (전체 판단에 사용)
    ftp_ps_cmd = "ps -ef | grep -E '[v]sftpd|[p]roftpd|[i]n\\.ftpd|ftpd' | grep -v grep"
    ftp_running_raw = run_shell(ftp_ps_cmd)
    ftp_service_status = "RUNNING" if ftp_running_raw else "NOT_RUNNING"

    for fpath in ftp_files:
        if os.path.exists(fpath):
            # 파일 전체 내용 (raw_output용)
            raw_content = run_shell(f"cat {fpath} 2>/dev/null")

            if "proftpd.conf" in fpath.lower():
                # ProFTPD RootLogin 설정 확인
                rootlogin = run_shell(f"grep -E '^[[:space:]]*RootLogin' {fpath} 2>/dev/null").strip()
                collected = rootlogin if rootlogin else "RootLogin not set (default usually off)"

                check_results.append({
                    "sub_check": f"ProFTPD RootLogin 설정 ({fpath})",
                    "config_file": fpath,
                    "collected_value": collected,
                    "raw_output": raw_content if raw_content else "NOT FOUND",
                    "service_status": ftp_service_status,   # FTP 서비스 상태 반영
                    "source_command": f"cat {fpath}"
                })
            else:
                # ftpusers 계열 파일에서 root 계정 확인
                root_line = run_shell(f"grep -E '^[[:space:]]*root' {fpath} 2>/dev/null").strip()
                
                if root_line:
                    collected = f"root 계정 등록됨: {root_line}"
                else:
                    collected = "root 계정 미등록 (접속 허용 위험)"

                check_results.append({
                    "sub_check": f"ftpusers root 등록 여부 ({fpath})",
                    "config_file": fpath,
                    "collected_value": collected,
                    "raw_output": raw_content if raw_content else "NOT FOUND",
                    "service_status": ftp_service_status,   # FTP 서비스 상태 반영
                    "source_command": f"cat {fpath}"
                })

    # ==================== 종합 현황 ====================
    summary = f"FTP Service: {ftp_service_status}"
    if ftp_service_status == "RUNNING":
        summary += " | Root FTP Access Risk: Check individual files"
    else:
        summary += " | Safe (FTP not running)"

    check_results.append({
        "sub_check": "FTP root 계정 접근제한 종합 현황",
        "config_file": "FTP Service + ftpusers files",
        "collected_value": summary,
        "raw_output": f"FTP Process:\n{ftp_running_raw if ftp_running_raw else 'No FTP process found'}",
        "service_status": ftp_service_status,
        "source_command": "ps -ef | grep -E '[v]sftpd|[p]roftpd|[i]n\\.ftpd|ftpd'"
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
                "item_code": "U-64",
                "item_name": "FTP 서비스 root 계정 접근제한",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
