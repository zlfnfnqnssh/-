#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-04 패스워드 파일 보호 점검 스크립트
- collected_value는 최대한 단순하게 (한 줄 위주)
- /etc/passwd의 경우 :x: 가 포함된 한 줄만 collected_value에 저장
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
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u04_result_{scan_id}.json")


def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except:
        return ""


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


def check_file_content(filepath: str) -> tuple:
    """파일 존재 여부와 전체 내용 반환"""
    if not os.path.exists(filepath):
        return "파일 없음", f"{filepath} 파일이 존재하지 않음"
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return "파일 존재", content
    except Exception:
        return "권한 없음 또는 오류", f"{filepath} 파일 읽기 실패"


def extract_first_matching_line(content: str, keyword: str) -> str:
    """keyword가 포함된 첫 번째 줄만 반환 (collected_value용)"""
    if not content:
        return "설정 없음"
    
    lines = content.splitlines()
    for line in lines:
        if keyword.lower() in line.lower():
            return line.strip()
    return f"{keyword} 설정 없음"


def save_json(result: Dict, output_dir: str, filename: str):
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] U-04 결과가 저장되었습니다: {filepath}")
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    check_results: List[Dict[str, Any]] = []

    # ==================== 1. ls /etc 결과 ====================
    etc_list_raw = run_shell("ls /etc 2>/dev/null")

    check_results.append({
        "sub_check": "Directory Listing (/etc)",
        "config_file": "/etc",
        "collected_value": "raw_output 데이터 확인 필요",
        "raw_output": etc_list_raw,
        "service_status": "N/A",
        "source_command": "ls /etc"
    })

    # ==================== 2. 주요 파일 점검 ====================
    os_checks = {
        "linux": [
            ("Shadow Password (/etc/passwd)", "/etc/passwd", "x:"),
            ("Shadow File Existence", "/etc/shadow", "root:"),
        ],
        "solaris": [
            ("Shadow Password (/etc/passwd)", "/etc/passwd", "x:"),
            ("Shadow File Existence", "/etc/shadow", "root:"),
        ],
        "aix": [
            ("Security Passwd File", "/etc/security/passwd", "password ="),
        ],
        "hpux": [
            ("Trusted Mode - tcb auth", "/tcb/files/auth/system/default", "u_maxtries"),
            ("Default Security", "/etc/default/security", "AUTH_MAXTRIES"),
            ("Shadow Password (/etc/passwd)", "/etc/passwd", "x:"),
        ]
    }

    checks = os_checks.get(target_os, [])

    for sub_check, config_file, keyword in checks:
        file_status, raw_output = check_file_content(config_file)
        
        if "파일 존재" in file_status:
            # collected_value는 keyword가 포함된 **첫 번째 줄만** 저장
            collected_value = extract_first_matching_line(raw_output, keyword)
            source_command = f"grep -i '{keyword}' {config_file}"
        else:
            collected_value = "파일 없음"
            source_command = f"cat {config_file}"

        check_results.append({
            "sub_check": sub_check,
            "config_file": config_file,
            "collected_value": collected_value,      # ← 한 줄만 나오도록 수정
            "raw_output": ("" if os.getenv("COMPACT_OUTPUT","0")=="1" else (raw_output if "파일 존재" in file_status else f"{config_file} 파일이 존재하지 않음")),
            "service_status": "INSTALLED" if os.path.exists("/etc/shadow") else "NOT_INSTALLED" if target_os == "linux" else "UNKNOWN",
            "source_command": source_command
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
                "item_code": "U-04",
                "item_name": "패스워드 파일 보호",
                "check_results": check_results
            }
        ]
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
