#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
U-01 root 계정 원격접속 제한 점검 스크립트
- Linux, Solaris, AIX, HP-UX 모두 지원
- JSON 파일로 저장 기능 추가
- 환경변수로 출력 경로 제어 가능
"""

import subprocess
import json
import os
import platform
import re
import sys
from datetime import datetime
from typing import List, Dict, Any

# ====================== 환경변수 설정 ======================
# OUTPUT_DIR: 결과를 저장할 폴더 (기본: 현재 디렉토리)
# OUTPUT_FILENAME: 저장할 파일명 (기본: u01_result_{scan_id}.json)
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILENAME_TEMPLATE = os.getenv("OUTPUT_FILENAME", "u01_result_{scan_id}.json")

def run_shell(cmd: str) -> str:
    """셸 명령어 안전하게 실행"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else ""
    except subprocess.TimeoutExpired:
        return "ERROR: Command timeout"
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
                    if "ubuntu" in content:
                        os_name = "Ubuntu"
                    elif "debian" in content:
                        os_name = "Debian"
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
    except PermissionError:
        return "권한 없음", f"{filepath} 파일 읽기 권한 없음"
    except Exception as e:
        return "오류", str(e)


def extract_keyword_with_cmd(content: str, keyword: str, filepath: str) -> tuple:
    """키워드 추출 + 실제 사용된 grep 명령어 반환"""
    if not content or "파일" in content[:30]:
        return "설정 없음", f"cat {filepath}"
    
    grep_cmd = f"grep -i '{keyword}' {filepath}"
    
    pattern = re.compile(rf'^.*{re.escape(keyword)}.*$', re.IGNORECASE | re.MULTILINE)
    matches = pattern.findall(content)
    
    if matches:
        collected = " | ".join(line.strip() for line in matches if line.strip())
    else:
        collected = f"{keyword} 설정 없음"
    
    return collected, grep_cmd


def save_json(result: Dict, output_dir: str, filename: str):
    """JSON 파일로 저장"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"[+] 결과가 저장되었습니다: {filepath}")
        return True
    except Exception as e:
        print(f"[-] 파일 저장 실패: {e}")
        return False


def main():
    scan_time = datetime.now()
    scan_id = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}"
    target_os, os_name = get_os_info()

    # ==================== OS별 점검 정의 ====================
    os_checks: Dict[str, List[tuple]] = {
        "linux": [
            ("Telnet PAM", "/etc/pam.d/login", "pam_securetty", "telnet"),
            ("Telnet securetty", "/etc/securetty", "pts", "telnet"),
            ("SSH", "/etc/ssh/sshd_config", "PermitRootLogin", "ssh"),
        ],
        "solaris": [
            ("Telnet", "/etc/default/login", "CONSOLE", "telnet"),
            ("SSH", "/etc/ssh/sshd_config", "PermitRootLogin", "ssh"),
        ],
        "aix": [
            ("Telnet", "/etc/security/user", "rlogin", "telnet"),
            ("SSH", "/etc/ssh/sshd_config", "PermitRootLogin", "ssh"),
        ],
        "hpux": [
            ("Telnet", "/etc/securetty", "console", "telnet"),
            ("SSH", "/etc/ssh/sshd_config", "PermitRootLogin", "ssh"),
        ]
    }

    checks = os_checks.get(target_os, [])

    check_results: List[Dict[str, Any]] = []

    for sub_check, config_file, keyword, svc in checks:
        # 서비스 상태 확인
        if target_os == "linux":
            if svc == "telnet":
                status_cmd = "dpkg -l 2>/dev/null | grep -E 'telnet' || rpm -qa 2>/dev/null | grep -E 'telnet'"
            else:
                status_cmd = "dpkg -l 2>/dev/null | grep -E 'openssh-server' || rpm -qa 2>/dev/null | grep -E 'openssh-server'"
            
            installed = "INSTALLED" if run_shell(status_cmd) else "NOT_INSTALLED"
            running = "RUNNING" if run_shell(f"systemctl is-active {svc}* 2>/dev/null") == "active" else "NOT_RUNNING"
            service_status = f"{installed}, {running}" if installed == "INSTALLED" else "NOT_INSTALLED"
        else:
            service_status = "UNKNOWN"

        # 파일 내용 가져오기
        file_status, raw_output = check_file_content(config_file)
        
        # collected_value + 실제 grep 명령어
        if "파일 존재" in file_status:
            collected_value, source_command = extract_keyword_with_cmd(raw_output, keyword, config_file)
        else:
            collected_value = f"{file_status} ({config_file})"
            source_command = f"cat {config_file}"

        check_results.append({
            "sub_check": sub_check,
            "config_file": config_file,
            "collected_value": collected_value,
            "raw_output": ("" if os.getenv("COMPACT_OUTPUT","0")=="1" else (raw_output if "파일 존재" in file_status else f"{config_file} 파일이 존재하지 않음")),
            "service_status": service_status,
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
                "item_code": "U-01",
                "item_name": "root 계정 원격접속 제한",
                "check_results": check_results
            }
        ]
    }

    # 화면에 출력
    print(json.dumps(result, ensure_ascii=False, indent=2))

    # JSON 파일로 저장
    filename = OUTPUT_FILENAME_TEMPLATE.format(scan_id=scan_id)
    save_json(result, OUTPUT_DIR, filename)


if __name__ == "__main__":
    main()
