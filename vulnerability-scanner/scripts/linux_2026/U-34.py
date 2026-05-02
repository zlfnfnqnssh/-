#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-34 DNS Zone Transfer 설정 점검 스크립트
- raw_output: 실제 명령어 실행 결과 그대로
- collected_value: re 정규표현식으로 핵심 값만 파싱
- 판단 로직 절대 포함하지 않음
"""
import subprocess
import json
import os
import platform
import re
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u34_result_{scan_id}.json")


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
        print(f"[+] U-34 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    # 1. DNS 서비스 (named) 프로세스 확인 - 주통기와 동일
    ps_cmd = "ps -ef | grep [n]amed"
    ps_raw = run_shell(ps_cmd)

    # 정규표현식으로 named 프로세스 라인만 추출
    if ps_raw:
        match = re.search(r'^\S+\s+\d+\s+.*named', ps_raw, re.MULTILINE)
        collected_ps = match.group(0).strip() if match else "NOT FOUND"
    else:
        collected_ps = "FILE NOT FOUND"

    check_results.append({
        "sub_check": "DNS 서비스 (named)",
        "config_file": "프로세스",
        "collected_value": collected_ps,
        "raw_output": ps_raw if ps_raw else "NOT FOUND",
        "service_status": "RUNNING" if ps_raw else "NOT_RUNNING",
        "source_command": ps_cmd
    })

    # 2. /etc/named.conf 파일 점검 (BIND 8/9 주요 설정 파일)
    named_conf = "/etc/named.conf"
    if os.path.exists(named_conf):
        conf_raw = run_shell("cat /etc/named.conf")
        
        # 정규표현식으로 allow-transfer 설정만 추출 (가장 핵심)
        allow_transfer_cmd = r"grep -E '^\s*allow-transfer' /etc/named.conf 2>/dev/null || echo 'NOT FOUND'"
        allow_transfer = run_shell(allow_transfer_cmd).strip()
        
        # 추가로 xfrnets (BIND4 스타일)도 함께 확인
        xfrnets_cmd = r"grep -E 'xfrnets' /etc/named.conf 2>/dev/null || echo 'NOT FOUND'"
        xfrnets = run_shell(xfrnets_cmd).strip()

        # collected_value: allow-transfer와 xfrnets를 핵심으로 정리
        collected_conf = f"allow-transfer: {allow_transfer} | xfrnets: {xfrnets}"
        
        check_results.append({
            "sub_check": "named.conf (Zone Transfer)",
            "config_file": "/etc/named.conf",
            "collected_value": collected_conf,
            "raw_output": conf_raw,
            "service_status": "RUNNING" if ps_raw else "NOT_RUNNING",
            "source_command": "cat /etc/named.conf | grep -E 'allow-transfer|xfrnets'"
        })
    else:
        check_results.append({
            "sub_check": "named.conf (Zone Transfer)",
            "config_file": "/etc/named.conf",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": "RUNNING" if ps_raw else "NOT_RUNNING",
            "source_command": "cat /etc/named.conf"
        })

    # 3. /etc/named.boot 파일 점검 (BIND 4.x 구버전)
    named_boot = "/etc/named.boot"
    if os.path.exists(named_boot):
        boot_raw = run_shell("cat /etc/named.boot")
        
        # 정규표현식으로 xfrnets 설정 추출
        xfrnets_boot_cmd = r"grep -E 'xfrnets' /etc/named.boot 2>/dev/null || echo 'NOT FOUND'"
        xfrnets_boot = run_shell(xfrnets_boot_cmd).strip()

        check_results.append({
            "sub_check": "named.boot (Zone Transfer)",
            "config_file": "/etc/named.boot",
            "collected_value": xfrnets_boot,
            "raw_output": boot_raw,
            "service_status": "RUNNING" if ps_raw else "NOT_RUNNING",
            "source_command": "cat /etc/named.boot | grep xfrnets"
        })
    else:
        check_results.append({
            "sub_check": "named.boot (Zone Transfer)",
            "config_file": "/etc/named.boot",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": "RUNNING" if ps_raw else "NOT_RUNNING",
            "source_command": "cat /etc/named.boot"
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
                "item_code": "U-34",
                "item_name": "DNS Zone Transfer 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
