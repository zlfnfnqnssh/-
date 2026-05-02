#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-25 NFS 접근 통제 점검 스크립트
- NFS 공유 설정 파일 점검 (/etc/exports, /etc/dfs/dfstab 등)
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u25_result_{scan_id}.json")


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
        print(f"[+] U-25 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 서비스 실행 여부 확인 (NFS 서버)
    _nfs_active = run_shell("systemctl is-active nfs-server 2>/dev/null || systemctl is-active nfs-kernel-server 2>/dev/null || systemctl is-active nfs 2>/dev/null")
    _nfs_which  = run_shell("which nfsd exportfs 2>/dev/null | head -1")
    nfs_svc = "RUNNING" if _nfs_active.strip() == "active" else               ("NOT_INSTALLED" if not _nfs_which else "NOT_RUNNING")


    # ==================== OS별 NFS 접근 통제 파일 목록 ====================
    if target_os == "linux" or target_os == "aix":
        nfs_files = [
            ("/etc/exports", "ls -l /etc/exports && cat /etc/exports"),
        ]
    elif target_os in ["solaris", "hpux"]:
        nfs_files = [
            ("/etc/dfs/dfstab", "ls -l /etc/dfs/dfstab && cat /etc/dfs/dfstab"),
            ("/etc/dfs/sharetab", "ls -l /etc/dfs/sharetab && cat /etc/dfs/sharetab"),
        ]
    else:
        nfs_files = [
            ("/etc/exports", "ls -l /etc/exports && cat /etc/exports"),
        ]

    # ==================== 파일 점검 ====================
    for filepath, cmd in nfs_files:
        # ls와 cat을 함께 실행
        full_result = run_shell(cmd)

        if full_result:
            # collected_value: 첫 번째 줄 (권한 정보)
            lines = full_result.splitlines()
            ls_line = next((line for line in lines if line.startswith('-') or line.startswith('d')), "권한 정보 없음")
            collected_value = ls_line.strip()
        else:
            collected_value = "FILE NOT FOUND"

        check_results.append({
            "sub_check": f"NFS 접근 통제 파일 ({os.path.basename(filepath)})",
            "config_file": filepath,
            "collected_value": collected_value,
            "raw_output": full_result if full_result else "파일이 존재하지 않습니다.",
            "service_status": nfs_svc,
            "source_command": cmd
        })

    # NFS 설정 파일이 하나도 없을 경우
    if not check_results:
        check_results.append({
            "sub_check": "NFS 접근 통제 파일",
            "config_file": "/etc/exports 또는 /etc/dfs/dfstab",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NFS 접근 통제 설정 파일이 존재하지 않습니다.",
            "service_status": nfs_svc,
            "source_command": "ls -l /etc/exports /etc/dfs/dfstab 2>/dev/null && cat /etc/exports /etc/dfs/dfstab 2>/dev/null"
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
                "item_code": "U-25",
                "item_name": "NFS 접근 통제",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
