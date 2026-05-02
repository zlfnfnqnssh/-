#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-59 (하) 숨겨진 파일 및 디렉토리 검색 및 제거 점검 스크립트
- 시스템 전체에서 숨겨진 파일(.으로 시작하는 파일)과 숨겨진 디렉토리 점검
- 주통기 명령어와 최대한 동일하게 find 명령어 사용
"""
import subprocess
import json
import os
import platform
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u59_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행 (긴 실행 시간 허용)"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except subprocess.TimeoutExpired:
        return "ERROR: Command timeout (60s)"
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
        print(f"[+] U-59 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # 1. 숨겨진 파일 검색 (주통기와 동일)
    hidden_files_cmd = 'find / -type f -name ".*" 2>/dev/null | head -200'
    hidden_files = run_shell(hidden_files_cmd)

    # 2. 숨겨진 디렉토리 검색 (주통기와 동일)
    hidden_dirs_cmd = 'find / -type d -name ".*" 2>/dev/null | head -100'
    hidden_dirs = run_shell(hidden_dirs_cmd)

    # collected_value: 의심스러운 숨김 파일/디렉토리 핵심 정보
    if hidden_files or hidden_dirs:
        suspicious = []
        if hidden_files:
            suspicious.append(f"Hidden Files: {len(hidden_files.splitlines())} found")
        if hidden_dirs:
            suspicious.append(f"Hidden Directories: {len(hidden_dirs.splitlines())} found")
        collected_value = "\n".join(suspicious)
    else:
        collected_value = "No hidden files or directories found"

    # 주요 점검 결과
    check_results.append({
        "sub_check": "숨겨진 파일 및 디렉토리 검색",
        "config_file": "전체 파일시스템",
        "collected_value": collected_value,
        "raw_output": f"=== Hidden Files ===\n{hidden_files}\n\n=== Hidden Directories ===\n{hidden_dirs}",
        "service_status": "N/A",
        "source_command": 'find / -type f -name ".*" 2>/dev/null && find / -type d -name ".*" 2>/dev/null'
    })

    # 상세 결과 분리 (파일이 많을 경우 판단에 유리)
    if hidden_files:
        check_results.append({
            "sub_check": "숨겨진 파일 목록",
            "config_file": "전체 파일시스템",
            "collected_value": hidden_files[:1000] + ("..." if len(hidden_files) > 1000 else ""),  # 너무 길면 자름
            "raw_output": hidden_files,
            "service_status": "N/A",
            "source_command": 'find / -type f -name ".*" 2>/dev/null | head -200'
        })

    if hidden_dirs:
        check_results.append({
            "sub_check": "숨겨진 디렉토리 목록",
            "config_file": "전체 파일시스템",
            "collected_value": hidden_dirs,
            "raw_output": hidden_dirs,
            "service_status": "N/A",
            "source_command": 'find / -type d -name ".*" 2>/dev/null | head -100'
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
                "item_code": "U-59",
                "item_name": "숨겨진 파일 및 디렉토리 검색 및 제거",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
