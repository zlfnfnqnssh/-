#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-24 NFS 서비스 비활성화 점검 스크립트
- NFS 관련 데몬 (nfsd, statd, lockd, mountd 등) 점검
- collected_value는 핵심 한 줄만 저장
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u24_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
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
        print(f"[+] U-24 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== NFS 관련 데몬 검색 ====================
    nfs_daemons = ["nfsd", "statd", "lockd", "mountd", "nfs", "rpcbind"]

    # 1. 프로세스 확인 (모든 OS 공통)
    ps_result = run_shell("ps -ef | grep -E 'nfsd|statd|lockd|mountd|nfs|rpcbind' | grep -v grep")

    if ps_result:
        check_results.append({
            "sub_check": "NFS 데몬 프로세스",
            "config_file": "프로세스",
            "collected_value": ps_result.splitlines()[0].strip() if ps_result.splitlines() else "NFS 프로세스 발견",
            "raw_output": ps_result,
            "service_status": "RUNNING",
            "source_command": "ps -ef | grep -E 'nfsd|statd|lockd|mountd|nfs|rpcbind' | grep -v grep"
        })
    else:
        check_results.append({
            "sub_check": "NFS 데몬 프로세스",
            "config_file": "프로세스",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "",
            "service_status": "NOT_RUNNING",
            "source_command": "ps -ef | grep -E 'nfsd|statd|lockd|mountd|nfs|rpcbind' | grep -v grep"
        })

    # 2. Linux - xinetd 또는 systemd 확인
    if target_os == "linux":
        # systemctl로 nfs 관련 서비스 확인
        nfs_services = run_shell("systemctl list-unit-files | grep -E 'nfs|rpc' 2>/dev/null")
        if nfs_services:
            check_results.append({
                "sub_check": "NFS 서비스 (systemd)",
                "config_file": "systemctl",
                "collected_value": nfs_services.splitlines()[0].strip() if nfs_services.splitlines() else "설정 없음",
                "raw_output": nfs_services,
                "service_status": "INSTALLED",
                "source_command": "systemctl list-unit-files | grep -E 'nfs|rpc'"
            })

    # 3. Solaris inetadm 방식
    if target_os == "solaris":
        inetadm_result = run_shell("inetadm | grep -E 'nfs|rpc' 2>/dev/null")
        if inetadm_result:
            check_results.append({
                "sub_check": "NFS 서비스 (inetadm)",
                "config_file": "inetadm",
                "collected_value": inetadm_result.strip(),
                "raw_output": inetadm_result,
                "service_status": "RUNNING",
                "source_command": "inetadm | grep -E 'nfs|rpc'"
            })

    # NFS 관련 서비스가 전혀 발견되지 않은 경우
    if len(check_results) == 1 and check_results[0]["collected_value"] == "FILE NOT FOUND":
        check_results.append({
            "sub_check": "NFS 서비스 전체",
            "config_file": "nfs 관련 데몬",
            "collected_value": "FILE NOT FOUND 또는 비활성화",
            "raw_output": "NFS 관련 서비스가 실행 중이거나 설정되어 있지 않습니다.",
            "service_status": "NOT_RUNNING",
            "source_command": "ps -ef | grep -E 'nfs|rpc' | grep -v grep && inetadm | grep -E 'nfs|rpc'"
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
                "item_code": "U-24",
                "item_name": "NFS 서비스 비활성화",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
