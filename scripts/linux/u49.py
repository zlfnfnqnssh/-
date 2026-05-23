#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-49 불필요한 계정 제거 점검 스크립트
- /etc/passwd에 등록된 모든 계정 확인
- 특히 불필요한 default 계정(lp, uucp, nuucp 등) 중점 점검
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u49_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
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
        print(f"[+] U-49 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    passwd_file = "/etc/passwd"

    if os.path.exists(passwd_file):
        passwd_raw = run_shell("cat /etc/passwd")

        # ==================== UID=0 제외 모든 계정 확인 ====================
        all_accounts = re.findall(r'^([^:]+):', passwd_raw, re.MULTILINE)
        
        # 불필요한 default 계정 목록 (주통기에서 자주 언급되는 계정들)
        suspicious_accounts = ['lp', 'uucp', 'nuucp', 'games', 'news', 'gopher', 
                               'ftp', 'nobody', 'nogroup', 'mail', 'postfix', 
                               'sync', 'shutdown', 'halt', 'operator']

        # UID=0인 계정 (root 포함)
        root_accounts = re.findall(r'^([^:]+):[^:]*:0:', passwd_raw, re.MULTILINE)

        # collected_value용: 불필요 의심 계정만 필터링
        found_suspicious = []
        for acc in suspicious_accounts:
            if acc in all_accounts:
                # 해당 계정의 전체 라인 추출
                line = re.search(rf'^{acc}:.*$', passwd_raw, re.MULTILINE)
                if line:
                    found_suspicious.append(line.group(0).strip())

        if found_suspicious:
            collected_value = "불필요 의심 계정 발견:\n" + "\n".join(found_suspicious)
        else:
            collected_value = "불필요 의심 default 계정 없음"

        check_results.append({
            "sub_check": "불필요한 계정 확인",
            "config_file": "/etc/passwd",
            "collected_value": collected_value,
            "raw_output": passwd_raw,
            "service_status": "N/A",
            "source_command": "cat /etc/passwd"
        })

        # 추가: UID=0 계정 목록 (참고용)
        if root_accounts:
            check_results.append({
                "sub_check": "UID=0 계정 목록",
                "config_file": "/etc/passwd",
                "collected_value": "\n".join(root_accounts),
                "raw_output": "\n".join(root_accounts),
                "service_status": "N/A",
                "source_command": "grep ':0:' /etc/passwd"
            })

    else:
        check_results.append({
            "sub_check": "불필요한 계정 확인",
            "config_file": "/etc/passwd",
            "collected_value": "FILE NOT FOUND",
            "raw_output": "NOT FOUND",
            "service_status": "N/A",
            "source_command": "cat /etc/passwd"
        })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "계정관리",
                "item_code": "U-49",
                "item_name": "불필요한 계정 제거",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
