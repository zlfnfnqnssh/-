#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-61 (하) FTP 서비스 확인 점검 스크립트
- FTP 서비스(vsftpd, proftpd, in.ftpd 등)가 실행 중인지 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u61_result_{scan_id}.json")


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
        print(f"[+] U-61 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 1. vsftpd 서비스 확인
    vsftpd_cmd = "ps -ef | grep -E '[v]sftpd' | grep -v grep"
    vsftpd_result = run_shell(vsftpd_cmd)

    check_results.append({
        "sub_check": "vsftpd 서비스 실행 상태",
        "config_file": "vsftpd process",
        "collected_value": vsftpd_result if vsftpd_result else "No vsftpd process",
        "raw_output": vsftpd_result if vsftpd_result else "NOT FOUND",
        "service_status": "RUNNING" if vsftpd_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[v]sftpd'"
    })

    # 2. proftpd 서비스 확인
    proftpd_cmd = "ps -ef | grep -E '[p]roftpd' | grep -v grep"
    proftpd_result = run_shell(proftpd_cmd)

    check_results.append({
        "sub_check": "proftpd 서비스 실행 상태",
        "config_file": "proftpd process",
        "collected_value": proftpd_result if proftpd_result else "No proftpd process",
        "raw_output": proftpd_result if proftpd_result else "NOT FOUND",
        "service_status": "RUNNING" if proftpd_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[p]roftpd'"
    })

    # 3. 일반 FTP 데몬 (in.ftpd 등) 확인
    ftpd_cmd = "ps -ef | grep -E '[i]n\\.ftpd|ftpd' | grep -v grep"
    ftpd_result = run_shell(ftpd_cmd)

    check_results.append({
        "sub_check": "일반 FTP (in.ftpd) 서비스 실행 상태",
        "config_file": "ftpd process",
        "collected_value": ftpd_result if ftpd_result else "No in.ftpd process",
        "raw_output": ftpd_result if ftpd_result else "NOT FOUND",
        "service_status": "RUNNING" if ftpd_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[i]n\\.ftpd|ftpd'"
    })

    # 4. 종합 FTP 서비스 현황 (판단에 가장 중요한 핵심 정보)
    ftp_services = []
    if vsftpd_result:
        ftp_services.append("vsftpd")
    if proftpd_result:
        ftp_services.append("proftpd")
    if ftpd_result:
        ftp_services.append("in.ftpd")

    if ftp_services:
        summary = f"FTP Services Running: {', '.join(ftp_services)}"
    else:
        summary = "No FTP service is running"

    check_results.append({
        "sub_check": "FTP 서비스 전체 현황",
        "config_file": "FTP services",
        "collected_value": summary,
        "raw_output": f"vsftpd:\n{vsftpd_result}\n\nproftpd:\n{proftpd_result}\n\nin.ftpd:\n{ftpd_result}",
        "service_status": "N/A",
        "source_command": "ps -ef | grep -E '[v]sftpd|[p]roftpd|[i]n\\.ftpd|ftpd' | grep -v grep"
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
                "item_code": "U-61",
                "item_name": "FTP 서비스 확인",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
