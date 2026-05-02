#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-51 계정이 존재하지 않는 GID 금지 점검 스크립트 (수정版)
- /etc/group + /etc/gshadow 모두 확인
- collected_value: 계정이 없는 불필요한 GID 중심으로 핵심 정보 제공
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u51_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
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
        print(f"[+] U-51 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()
    check_results: List[Dict[str, Any]] = []

    group_file = "/etc/group"
    gshadow_file = "/etc/gshadow"
    passwd_file = "/etc/passwd"

    if os.path.exists(passwd_file):
        passwd_raw = run_shell("cat /etc/passwd")

        # passwd에 사용 중인 GID 수집
        used_gids = set()
        for line in passwd_raw.splitlines():
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 4:
                    try:
                        used_gids.add(int(parts[3]))
                    except ValueError:
                        continue

        # ==================== /etc/group 확인 ====================
        if os.path.exists(group_file):
            group_raw = run_shell("cat /etc/group")
            orphaned_groups = []

            for line in group_raw.splitlines():
                if line.strip() and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        group_name = parts[0]
                        try:
                            gid = int(parts[2])
                        except ValueError:
                            continue

                        # GID가 passwd에 없는 경우 + 시스템 그룹(GID < 1000)은 제외하고 중점 점검
                        if gid not in used_gids and gid >= 100:
                            orphaned_groups.append(line.strip())

            if orphaned_groups:
                collected_group = f"계정이 존재하지 않는 GID 발견 ({len(orphaned_groups)}개):\n" + "\n".join(orphaned_groups)
            else:
                collected_group = "계정이 존재하지 않는 불필요한 GID 없음"

            check_results.append({
                "sub_check": "계정이 없는 GID (group 파일)",
                "config_file": "/etc/group",
                "collected_value": collected_group,
                "raw_output": group_raw,
                "service_status": "N/A",
                "source_command": "cat /etc/group"
            })

        # ==================== /etc/gshadow 확인 (Linux) ====================
        if target_os == "linux" and os.path.exists(gshadow_file):
            gshadow_raw = run_shell("cat /etc/gshadow")
            
            check_results.append({
                "sub_check": "그룹 shadow 파일 (gshadow)",
                "config_file": "/etc/gshadow",
                "collected_value": "gshadow 파일 존재",
                "raw_output": gshadow_raw,
                "service_status": "N/A",
                "source_command": "cat /etc/gshadow"
            })

        # ==================== 사용 중인 GID 요약 ====================
        check_results.append({
            "sub_check": "사용 중인 GID 요약",
            "config_file": "/etc/passwd",
            "collected_value": f"총 {len(used_gids)}개의 GID가 사용 중",
            "raw_output": f"사용 중인 GID 목록: {sorted(list(used_gids))[:100]}",
            "service_status": "N/A",
            "source_command": "cat /etc/passwd | cut -d: -f4 | sort -n | uniq"
        })

    else:
        check_results.append({
            "sub_check": "계정이 없는 GID 확인",
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
                "item_code": "U-51",
                "item_name": "계정이 존재하지 않는 GID 금지",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
