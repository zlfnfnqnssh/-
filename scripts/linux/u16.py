#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-16 /dev에 존재하지 않는 device 파일 점검 스크립트
- /dev 디렉토리 내 major/minor number가 없는 파일 검색
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u16_result_{scan_id}.json")


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
        print(f"[+] U-16 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== /dev 내 존재하지 않는 device 파일 검색 ====================
    # 주통기 가이드: find /dev -type f -exec ls -l {} \;
    find_cmd = 'find /dev -type f -exec ls -l {} \\; 2>/dev/null | head -80'

    result_raw = run_shell(find_cmd)

    if "TIMEOUT" in result_raw:
        collected_value = "검색 시간 초과"
        raw_output = "find 명령어가 제한 시간(60초)을 초과하여 중단되었습니다."
    elif result_raw.strip():
        lines = result_raw.splitlines()
        count = len(lines)
        collected_value = f"{count}개 발견"
        raw_output = result_raw
    else:
        collected_value = "없음"
        raw_output = "/dev 디렉토리에 존재하지 않는 device 파일이 없습니다."

    check_results.append({
        "sub_check": "/dev 내 존재하지 않는 device 파일",
        "config_file": "/dev",
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
                "item_code": "U-16",
                "item_name": "/dev에 존재하지 않는 device 파일 점검",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
