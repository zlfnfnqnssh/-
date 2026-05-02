#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-13 SUID, SGID 설정 파일 점검 스크립트
- 불필요한 SUID/SGID 설정 여부 점검
- collected_value는 순수 파싱 결과만 저장
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u13_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except subprocess.TimeoutExpired:
        return "TIMEOUT: find 명령어가 너무 오래 걸림"
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
        print(f"[+] U-13 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== SUID/SGID 검색 명령어 (주통기 가이드 기반) ====================
    # find 명령어로 root 소유의 SUID(4000) 또는 SGID(2000) 파일 검색
    find_cmd = r'find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -ls 2>/dev/null | head -100'

    result_raw = run_shell(find_cmd)

    if "TIMEOUT" in result_raw:
        collected_value = "검색 시간 초과"
        raw_output = "find 명령어가 제한 시간을 초과하여 중단되었습니다."
    elif result_raw.strip():
        lines = result_raw.splitlines()
        count = len(lines)
        collected_value = f"{count}개 발견"
        raw_output = result_raw
    else:
        collected_value = "없음"
        raw_output = "SUID/SGID가 설정된 파일이 없습니다."

    check_results.append({
        "sub_check": "SUID/SGID 설정 파일 검색",
        "config_file": "전체 파일시스템",
        "collected_value": collected_value,        # 순수 결과만
        "raw_output": raw_output,
        "service_status": "N/A",
        "source_command": find_cmd
    })

    # ==================== 최종 JSON ====================
    result = {
        "scan_id": scan_id,
        "scan_date": scan_time.isoformat(),
        "target_os": target_os,
        "os_name": os_name,
        "items": [
            {
                "category": "파일 및 디렉토리 관리",        # "2." 삭제
                "item_code": "U-13",
                "item_name": "SUID, SGID, 설정 파일점검",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
