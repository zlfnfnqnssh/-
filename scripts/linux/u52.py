#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-52 (중) 동일한 UID 금지 점검 스크립트
- /etc/passwd 파일에서 동일한 UID를 가진 서로 다른 사용자 계정 존재 여부 점검
- process substitution 제거 → 모든 유닉스(/bin/sh) 환경에서 안정적으로 동작
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u52_result_{scan_id}.json")


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
        print(f"[+] U-52 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    passwd_file = "/etc/passwd"

    if os.path.exists(passwd_file):
        # 1. 전체 passwd 파일 내용 (raw_output용)
        cat_cmd = f"cat {passwd_file}"
        raw_passwd = run_shell(cat_cmd)

        # 2. 중복 UID 찾기 (호환성 높은 방식)
        duplicate_cmd = "awk -F: '{print $3}' /etc/passwd | sort | uniq -d"
        duplicate_uids = run_shell(duplicate_cmd).strip()

        if duplicate_uids:
            # 중복 UID가 있을 경우 상세 정보 추출 (process substitution 제거)
            detail_cmd = f"""
UIDS="{duplicate_uids}"
awk -F: '
    BEGIN {{
        split("{duplicate_uids}", arr, "\n")
        for(i in arr) if(arr[i] != "") dup[arr[i]] = 1
    }}
    $3 in dup {{ print $1 ":" $3 }}
' /etc/passwd
"""
            detail_result = run_shell(detail_cmd).strip()
            collected_value = detail_result if detail_result else duplicate_uids
        else:
            collected_value = "No duplicate UID"
            detail_result = ""

        # 주요 체크 결과
        check_results.append({
            "sub_check": "중복 UID 점검",
            "config_file": "/etc/passwd",
            "collected_value": collected_value,
            "raw_output": raw_passwd if raw_passwd else "NOT FOUND",
            "service_status": "N/A",
            "source_command": "cat /etc/passwd && awk -F: '{print $3}' /etc/passwd | sort | uniq -d"
        })

        # 중복 상세 정보 (존재할 경우 별도 sub_check)
        if detail_result:
            check_results.append({
                "sub_check": "중복 UID 상세 (사용자:UID)",
                "config_file": "/etc/passwd",
                "collected_value": detail_result,
                "raw_output": detail_result,
                "service_status": "N/A",
                "source_command": "awk -F: '{uid[$3]++} END {for(u in uid) if(uid[u]>1) print u}' /etc/passwd | xargs -I {} sh -c 'awk -F: \"$3==\\\"\"{}\"\\\"\" {print $1 \":\" $3}' /etc/passwd'"
            })
    else:
        check_results.append({
            "sub_check": "중복 UID 점검",
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
                "item_code": "U-52",
                "item_name": "동일한 UID 금지",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
