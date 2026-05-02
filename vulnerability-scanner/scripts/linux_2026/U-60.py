#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-60 (중) SSH 원격접속 허용 점검 스크립트
- SSH 서비스가 실행 중인지 확인
- Telnet, FTP 등 안전하지 않은 원격접속 서비스가 동시에 실행 중인지 확인
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u60_result_{scan_id}.json")


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
        print(f"[+] U-60 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 1. SSH 서비스 실행 여부 확인
    ssh_ps_cmd = "ps -ef | grep -E '[s]shd' | grep -v grep"
    ssh_result = run_shell(ssh_ps_cmd)

    check_results.append({
        "sub_check": "SSH 서비스 실행 상태",
        "config_file": "sshd process",
        "collected_value": ssh_result if ssh_result else "No SSH process",
        "raw_output": ssh_result if ssh_result else "NOT FOUND",
        "service_status": "RUNNING" if ssh_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[s]shd'"
    })

    # 2. Telnet 서비스 실행 여부 (위험 서비스)
    telnet_ps_cmd = "ps -ef | grep -E '[t]elnetd|[i]n.telnetd' | grep -v grep"
    telnet_result = run_shell(telnet_ps_cmd)

    check_results.append({
        "sub_check": "Telnet 서비스 실행 상태",
        "config_file": "telnetd process",
        "collected_value": telnet_result if telnet_result else "No Telnet process",
        "raw_output": telnet_result if telnet_result else "NOT FOUND",
        "service_status": "RUNNING" if telnet_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[t]elnetd'"
    })

    # 3. FTP 서비스 실행 여부 (위험 서비스)
    ftp_ps_cmd = "ps -ef | grep -E '[f]tpd|[i]n.ftpd|vsftpd|proftpd' | grep -v grep"
    ftp_result = run_shell(ftp_ps_cmd)

    check_results.append({
        "sub_check": "FTP 서비스 실행 상태",
        "config_file": "ftpd process",
        "collected_value": ftp_result if ftp_result else "No FTP process",
        "raw_output": ftp_result if ftp_result else "NOT FOUND",
        "service_status": "RUNNING" if ftp_result else "NOT_RUNNING",
        "source_command": "ps -ef | grep -E '[f]tpd|vsftpd|proftpd'"
    })

    # 4. 종합 판단을 위한 핵심 정보 (SSH 사용 + 위험 서비스 존재 여부)
    dangerous_services = []
    if telnet_result:
        dangerous_services.append("Telnet")
    if ftp_result:
        dangerous_services.append("FTP")

    summary = f"SSH: {'RUNNING' if ssh_result else 'NOT_RUNNING'}"
    if dangerous_services:
        summary += f", Dangerous Services: {', '.join(dangerous_services)}"

    check_results.append({
        "sub_check": "원격접속 프로토콜 종합 현황",
        "config_file": "SSH / Telnet / FTP",
        "collected_value": summary,
        "raw_output": f"SSH:\n{ssh_result}\n\nTelnet:\n{telnet_result}\n\nFTP:\n{ftp_result}",
        "service_status": "N/A",
        "source_command": "ps -ef | grep -E '[s]shd|[t]elnetd|[f]tpd'"
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
                "item_code": "U-60",
                "item_name": "SSH 원격접속 허용",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
