#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-44 root 이외의 UID가 ‘0’ 금지 점검 스크립트
- UID=0인 계정( root 제외 ) 존재 여부 점검
- collected_value: UID=0인 계정 라인만 추출 (핵심 판단 정보)
- raw_output: 전체 /etc/passwd 내용
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u44_result_{scan_id}.json")


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
        print(f"[+] U-44 결과가 저장되었습니다: {filepath}")
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

        # ==================== 정규표현식으로 UID=0인 계정만 추출 ====================
        # 형식: 계정명:x:0:...
        uid_zero_lines = re.findall(r'^([^:]+):[^:]*:0:', passwd_raw, re.MULTILINE)

        if uid_zero_lines:
            # UID=0인 모든 계정 라인 전체를 collected_value에 저장
            collected_lines = []
            for line in passwd_raw.splitlines():
                if re.match(r'^([^:]+):[^:]*:0:', line):
                    collected_lines.append(line.strip())
            collected_value = "\n".join(collected_lines)
        else:
            collected_value = "UID=0 인 계정 없음 (root만 존재)"

        # source_command: 실제 grep 명령어 형태로 저장
        source_cmd = "grep -E '^[^:]+:[^:]*:0:' /etc/passwd"

        check_results.append({
            "sub_check": "UID 0 계정 확인",
            "config_file": "/etc/passwd",
            "collected_value": collected_value,
            "raw_output": passwd_raw,
            "service_status": "N/A",
            "source_command": source_cmd
        })

    else:
        check_results.append({
            "sub_check": "UID 0 계정 확인",
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
                "item_code": "U-44",
                "item_name": "root 이외의 UID가 ‘0’ 금지",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
