#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-27 RPC 서비스 확인 점검 스크립트
- 불필요한 RPC 서비스 (rpc.cmsd, ttdbserver, rusersd 등) 점검
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u27_result_{scan_id}.json")


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
        print(f"[+] U-27 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 불필요한 RPC 서비스 목록 (주통기 기준)
    rpc_services = [
        "rpc.cmsd", "rpc.ttdbserverd", "sadmind", "rusersd", "walld", 
        "sprayd", "rstatd", "rpc.nisd", "rexd", "rpc.pcnfsd", 
        "rpc.statd", "rpc.ypupdated", "rpc.rquotad", "kcms_server", "cachefsd"
    ]

    # ==================== 1. inetd.conf 방식 ====================
    inetd_cmd = f"grep -E '{'|'.join(rpc_services)}' /etc/inetd.conf 2>/dev/null"
    inetd_result = run_shell(inetd_cmd)

    if inetd_result:
        for line in inetd_result.splitlines():
            if line.strip() and not line.strip().startswith('#'):
                check_results.append({
                    "sub_check": "RPC 서비스 (inetd.conf)",
                    "config_file": "/etc/inetd.conf",
                    "collected_value": line.strip(),
                    "raw_output": line.strip(),
                    "service_status": "RUNNING",
                    "source_command": inetd_cmd
                })
    else:
        check_results.append({
            "sub_check": "RPC 서비스 (inetd.conf)",
            "config_file": "/etc/inetd.conf",
            "collected_value": "FILE NOT FOUND 또는 비활성화",
            "raw_output": "",
            "service_status": "NOT_RUNNING",
            "source_command": inetd_cmd
        })

    # ==================== 2. xinetd 방식 (Linux) ====================
    if target_os == "linux":
        for svc in rpc_services:
            # xinetd.d 디렉토리 내 해당 서비스 파일 검색
            xinetd_files = run_shell(f"ls /etc/xinetd.d/ 2>/dev/null | grep -i {svc.split('.')[0]}")
            if xinetd_files:
                for f in xinetd_files.split():
                    path = f"/etc/xinetd.d/{f}"
                    cat_result = run_shell(f"cat {path} 2>/dev/null")
                    if cat_result:
                        collected = cat_result.splitlines()[0].strip()
                        check_results.append({
                            "sub_check": f"RPC 서비스 (xinetd/{f})",
                            "config_file": path,
                            "collected_value": collected,
                            "raw_output": cat_result,
                            "service_status": "INSTALLED",
                            "source_command": f"cat {path}"
                        })

    # ==================== 3. Solaris inetadm 방식 ====================
    if target_os == "solaris":
        inetadm_cmd = f"inetadm | grep -E '{'|'.join(rpc_services)}' 2>/dev/null"
        inetadm_result = run_shell(inetadm_cmd)

        if inetadm_result:
            check_results.append({
                "sub_check": "RPC 서비스 (inetadm)",
                "config_file": "inetadm",
                "collected_value": inetadm_result.strip(),
                "raw_output": inetadm_result,
                "service_status": "RUNNING",
                "source_command": inetadm_cmd
            })

    # RPC 서비스가 전혀 발견되지 않은 경우
    if not any("RPC 서비스" in item["sub_check"] for item in check_results if "FILE NOT FOUND" not in item.get("collected_value", "")):
        check_results.append({
            "sub_check": "RPC 서비스 전체",
            "config_file": "inetd / xinetd / inetadm",
            "collected_value": "FILE NOT FOUND 또는 비활성화",
            "raw_output": "불필요한 RPC 서비스가 설정되어 있지 않습니다.",
            "service_status": "NOT_RUNNING",
            "source_command": "grep -E 'rpc.cmsd|rpc.ttdbserver|sadmind|rusersd' /etc/inetd.conf /etc/xinetd.d/* && inetadm | grep rpc"
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
                "item_code": "U-27",
                "item_name": "RPC 서비스 확인",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
