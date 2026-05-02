#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-06 파일 및 디렉토리 소유자 설정 점검 스크립트
- timeout 문제를 해결하기 위해 검색 범위 제한 + timeout 120초 적용
"""

import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u06_result_{scan_id}.json")


def run_shell(cmd: str, timeout_sec: int = 120) -> str:
    """셸 명령어 실행 (timeout 120초)"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout_sec
        )
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except subprocess.TimeoutExpired:
        return "TIMEOUT: find 명령어가 너무 오래 걸려 중단됨"
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
        print(f"[+] U-06 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 검색 범위를 주요 디렉토리로 제한 (전체 / 대신)
    search_paths = ["/", "/home", "/root", "/var", "/etc", "/opt", "/usr"]

    if target_os == "linux":
        commands = [
            ("nouser files", f"find {' '.join(search_paths)} -nouser -xdev -print 2>/dev/null | head -50"),
            ("nogroup files", f"find {' '.join(search_paths)} -nogroup -xdev -print 2>/dev/null | head -50"),
        ]
    else:
        # Solaris, AIX, HP-UX는 기존 방식 유지 (필요시 조정)
        commands = [
            ("nouser or nogroup", "find / -nouser -o -nogroup -xdev -ls 2>/dev/null | head -30"),
        ]

    for sub_check, find_cmd in commands:
        result_raw = run_shell(find_cmd, timeout_sec=120)

        if "TIMEOUT" in result_raw:
            collected_value = "검색 시간 초과"
            raw_output = "find 명령어가 제한 시간(120초)을 초과하여 중단되었습니다."
        elif result_raw.strip():
            lines = result_raw.splitlines()
            count = len(lines)
            collected_value = f"{count}개 발견"
            raw_output = result_raw
        else:
            collected_value = "없음"
            raw_output = "소유자 또는 그룹이 없는 파일/디렉토리가 없습니다."

        check_results.append({
            "sub_check": sub_check,
            "config_file": "주요 디렉토리",
            "collected_value": collected_value,
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
                "category": "파일 및 디렉토리 관리",
                "item_code": "U-06",
                "item_name": "파일 및 디렉토리 소유자 설정",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
