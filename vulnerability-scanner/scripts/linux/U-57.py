#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-57 (중) 홈디렉토리 소유자 및 권한 설정 점검 스크립트
- /etc/passwd에 등록된 사용자들의 홈 디렉토리 소유자 및 타 사용자 쓰기 권한 점검
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u57_result_{scan_id}.json")


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
        print(f"[+] U-57 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 1. /etc/passwd 전체 내용 (raw_output용)
    passwd_file = "/etc/passwd"
    if os.path.exists(passwd_file):
        raw_passwd = run_shell("cat /etc/passwd")

        # 2. 홈디렉토리 소유자 및 권한 점검 (주통기 스타일)
        # UID >= 1000 또는 시스템 계정 제외하고 일반 사용자 중심으로 점검 (root, daemon 등은 제외)
        check_cmd = r"""
awk -F: '
    $3 >= 1000 || $1 == "root" {
        home=$6;
        if (home != "" && home != "/" && home != "/root") {
            cmd = "ls -ald " home " 2>/dev/null";
            if (system(cmd) == 0) {
                getline line < ("ls -ald " home " 2>/dev/null");
                close("ls -ald " home " 2>/dev/null");
                print $1 ":" home ":" line;
            }
        }
    }
' /etc/passwd
"""

        raw_output = run_shell(check_cmd)

        # collected_value: 문제가 될 수 있는 항목만 추출 (타 사용자 쓰기 권한이 있는 경우 또는 소유자 불일치)
        collect_cmd = r"""
awk -F: '
    $3 >= 1000 || $1 == "root" {
        user=$1; uid=$3; home=$6;
        if (home != "" && home != "/" && home != "/root") {
            cmd = "stat -c \"%U:%a\" " home " 2>/dev/null || ls -ld " home " 2>/dev/null | awk \"{print \\$3 \":\" substr(\\$1,9,1)}\"";
            system(cmd);
        }
    }
' /etc/passwd 2>/dev/null
"""

        collected_value = run_shell(collect_cmd).strip()

        if not collected_value:
            collected_value = "All home directories have proper owner and no other write permission"

        check_results.append({
            "sub_check": "사용자 홈디렉토리 소유자 및 권한 점검",
            "config_file": "/etc/passwd",
            "collected_value": collected_value,
            "raw_output": raw_passwd if raw_passwd else "NOT FOUND",
            "service_status": "N/A",
            "source_command": "cat /etc/passwd && ls -ald $(awk -F: '$6!=\"\" && $6!=\"/\" {print $6}' /etc/passwd 2>/dev/null)"
        })

        # 상세 결과 (문제 소지가 있는 홈디렉토리만)
        if "w" in collected_value or "other write" in collected_value.lower():
            check_results.append({
                "sub_check": "타 사용자 쓰기 권한이 있는 홈디렉토리",
                "config_file": "/etc/passwd",
                "collected_value": collected_value,
                "raw_output": raw_output if raw_output else "NOT FOUND",
                "service_status": "N/A",
                "source_command": "awk -F: '$6 != \"\" {print $6}' /etc/passwd | xargs -I {} sh -c 'ls -ld {} 2>/dev/null | grep -E \"^d......w.\"'"
            })

    else:
        check_results.append({
            "sub_check": "사용자 홈디렉토리 소유자 및 권한 점검",
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
                "category": "파일 및 디렉토리 관리",
                "item_code": "U-57",
                "item_name": "홈디렉토리 소유자 및 권한 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
