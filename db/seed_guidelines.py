#!/usr/bin/env python3
"""
seed_guidelines.py
------------------
주통기 PDF가 파싱된 것처럼 guidelines DB를 미리 채워둡니다.
다른 팀원의 RAG 파싱 결과가 들어오면 이 데이터를 덮어쓰면 됩니다.

실행:
    python3 db/seed_guidelines.py
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = os.getenv("GUIDELINE_DB_PATH", "./db/guidelines.db")
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────────────────────
# 주통기 가이드라인 데이터
# (주요통신기반시설 기술적 취약점 분석·평가 방법 상세 가이드 기준)
# ──────────────────────────────────────────────────────────────

GUIDELINES = [
    # (item_code, item_name, category, content, check_point, standard, severity, vuln_keywords, ok_keywords)
    ("U-01", "root 계정 원격접속 제한", "계정관리",
     "시스템 원격접속 시 root 계정으로 직접 로그인하는 것을 제한해야 한다.",
     "① /etc/securetty 파일에 pts/0~pts/x 항목 존재 여부 확인\n② /etc/ssh/sshd_config 파일의 PermitRootLogin 설정 확인\n③ /etc/pam.d/login 파일의 pam_securetty.so 설정 확인",
     "양호: sshd_config에 PermitRootLogin no 설정 또는 SSH 서비스 미사용\n취약: PermitRootLogin yes 이거나 설정 없음",
     "상",
     "permitrootlogin yes",
     "permitrootlogin no,permitrootlogin prohibit-password"),

    ("U-02", "패스워드 복잡성 설정", "계정관리",
     "사용자 계정 패스워드 작성 시 복잡성(대소문자, 숫자, 특수문자 조합) 규칙이 적용되어야 한다.",
     "① /etc/pam.d/system-auth 또는 /etc/pam.d/common-password 파일 확인\n② pam_pwquality.so 또는 pam_cracklib.so 설정 확인\n③ minlen, dcredit, ucredit, lcredit, ocredit 값 확인",
     "양호: minlen=8 이상, 영문/숫자/특수문자 각 1자 이상 조합 설정\n취약: 패스워드 복잡성 미설정",
     "상",
     "minlen=0,minlen=1,minlen=2,minlen=3,minlen=4,minlen=5,minlen=6,minlen=7",
     "minlen=8,minlen=9,minlen=10,minlen=12,minlen=14,pam_pwquality,pam_cracklib"),

    ("U-03", "계정 잠금 임계값 설정", "계정관리",
     "일정 횟수 이상 로그인 실패 시 계정이 잠금되어야 한다.",
     "① /etc/pam.d/system-auth 또는 /etc/pam.d/common-auth 파일 확인\n② pam_tally2.so 또는 pam_faillock.so 설정 확인\n③ deny 값(잠금 임계값) 확인",
     "양호: deny=5 이하(5회 이하 실패 시 잠금)\n취약: 계정 잠금 정책 미설정 또는 deny 값이 너무 큰 경우",
     "상",
     "deny=0",
     "deny=3,deny=4,deny=5,pam_tally2,pam_faillock"),

    ("U-04", "패스워드 파일 보호", "계정관리",
     "/etc/passwd 파일에 패스워드가 직접 저장되지 않고 shadow 패스워드를 사용해야 한다.",
     "① /etc/passwd 파일에서 두 번째 필드(패스워드 필드) 확인\n② shadow 패스워드 사용 여부: 두 번째 필드가 'x'이어야 함\n③ /etc/shadow 파일 존재 및 권한 확인",
     "양호: /etc/passwd의 패스워드 필드가 'x'로 표시(shadow 사용)\n취약: 패스워드가 암호화되어 직접 저장된 경우",
     "상",
     "passwd 필드 직접 저장",
     "shadow,x:"),

    ("U-05", "root 이외의 UID 0 금지", "계정관리",
     "root(UID=0) 외의 계정에 UID 0이 부여되지 않아야 한다.",
     "① /etc/passwd 파일에서 UID가 0인 계정 목록 확인\n② root 외의 계정에 UID 0이 존재하는지 확인",
     "양호: UID 0 계정이 root 하나만 존재\n취약: root 외 UID 0 계정 존재",
     "상",
     "uid=0 복수",
     "root:x:0:0"),

    ("U-06", "root 계정 PATH 환경변수 설정", "계정관리",
     "root 계정의 PATH 환경변수에 현재 디렉토리(.) 또는 비표준 경로가 포함되지 않아야 한다.",
     "① root 계정 PATH 환경변수 확인\n② PATH에 '.' 또는 '::'가 포함되어 있는지 확인",
     "양호: PATH에 '.' 또는 '::'가 없음\n취약: PATH에 '.' 또는 '::'가 포함됨",
     "하",
     "path=.:,path=::,:.:",
     ""),

    ("U-07", "파일 및 디렉토리 소유자 설정", "파일및디렉토리관리",
     "소유자가 없는(삭제된 계정 소유) 파일 및 디렉토리가 존재하지 않아야 한다.",
     "① 소유자가 없는 파일 및 디렉토리 검색\n② find / -nouser -o -nogroup 명령으로 확인",
     "양호: 소유자 없는 파일/디렉토리 없음\n취약: 소유자 없는 파일/디렉토리 존재",
     "하",
     "nouser,nogroup",
     ""),

    ("U-08", "/etc/passwd 파일 소유자 및 권한 설정", "파일및디렉토리관리",
     "/etc/passwd 파일의 소유자는 root이고 권한은 644 이하여야 한다.",
     "① /etc/passwd 파일 소유자 확인\n② /etc/passwd 파일 권한 확인(644 이하)",
     "양호: 소유자 root, 권한 644\n취약: 소유자 root가 아니거나 권한이 644 초과",
     "상",
     "permission 646,permission 666,permission 777",
     "644,root"),

    ("U-09", "/etc/shadow 파일 소유자 및 권한 설정", "파일및디렉토리관리",
     "/etc/shadow 파일의 소유자는 root이고 권한은 400 이하여야 한다.",
     "① /etc/shadow 파일 소유자 확인\n② /etc/shadow 파일 권한 확인(400 이하)",
     "양호: 소유자 root, 권한 400 또는 000\n취약: 소유자 root가 아니거나 권한이 400 초과",
     "상",
     "permission 644,permission 666",
     "400,000,root"),

    ("U-10", "/etc/hosts 파일 소유자 및 권한 설정", "파일및디렉토리관리",
     "/etc/hosts 파일의 소유자는 root이고 권한은 600 이하여야 한다.",
     "① /etc/hosts 파일 소유자 확인\n② /etc/hosts 파일 권한 확인",
     "양호: 소유자 root, 권한 600 이하\n취약: 소유자 root가 아니거나 권한 초과",
     "하",
     "",
     "600,644,root"),

    ("U-11", "/etc/(x)inetd.conf 파일 소유자 및 권한 설정", "파일및디렉토리관리",
     "/etc/inetd.conf 또는 /etc/xinetd.conf 파일 소유자는 root이고 권한은 600 이하여야 한다.",
     "① /etc/inetd.conf 또는 /etc/xinetd.conf 파일 확인\n② 소유자 및 권한 확인",
     "양호: 소유자 root, 권한 600 이하\n취약: 소유자 root가 아니거나 권한 초과",
     "상",
     "",
     "600,root"),

    ("U-12", "/etc/syslog.conf 파일 소유자 및 권한 설정", "파일및디렉토리관리",
     "/etc/syslog.conf(또는 rsyslog.conf) 파일 소유자는 root이고 권한은 640 이하여야 한다.",
     "① 파일 존재 및 소유자 확인\n② 권한 확인(640 이하)",
     "양호: 소유자 root, 권한 640 이하\n취약: 소유자 root가 아니거나 권한 640 초과",
     "하",
     "",
     "640,600,root"),

    ("U-13", "/etc/services 파일 소유자 및 권한 설정", "파일및디렉토리관리",
     "/etc/services 파일 소유자는 root이고 권한은 644 이하여야 한다.",
     "① /etc/services 파일 소유자 확인\n② 권한 확인",
     "양호: 소유자 root, 권한 644 이하\n취약: 소유자 root가 아니거나 권한 644 초과",
     "하",
     "",
     "644,root"),

    ("U-14", "SUID, SGID, Sticky bit 설정 파일 점검", "파일및디렉토리관리",
     "불필요하거나 의심스러운 SUID/SGID 설정 파일이 없어야 한다.",
     "① SUID/SGID 설정 파일 목록 확인\n② find / -perm -4000 -o -perm -2000 명령 사용\n③ 불필요한 파일에 SUID/SGID 설정 여부 확인",
     "양호: 불필요한 SUID/SGID 파일 없음\n취약: 불필요한 파일에 SUID/SGID 설정",
     "중",
     "suid 불필요,sgid 불필요",
     ""),

    ("U-15", "사용자, 시스템 시작파일 및 환경변수 파일 소유자 및 권한 설정", "파일및디렉토리관리",
     "사용자 홈 디렉토리의 시작 파일(.bashrc, .profile 등)에 쓰기 권한이 적절히 설정되어야 한다.",
     "① 각 사용자의 홈 디렉토리 내 시작 파일 확인\n② 타 사용자의 쓰기 권한 여부 확인",
     "양호: 소유자만 쓰기 가능\n취약: 타 사용자 쓰기 권한 존재",
     "하",
     "world writable",
     ""),

    ("U-16", "world writable 파일 점검", "파일및디렉토리관리",
     "시스템 내 불필요한 world writable 파일이 없어야 한다.",
     "① find / -perm -2 -type f 명령으로 world writable 파일 확인\n② 불필요한 파일 존재 여부 판단",
     "양호: 불필요한 world writable 파일 없음\n취약: 불필요한 world writable 파일 존재",
     "하",
     "world writable 존재",
     ""),

    ("U-17", "$HOME/.rhosts, hosts.equiv 사용 금지", "서비스관리",
     ".rhosts 파일과 /etc/hosts.equiv 파일이 존재하지 않거나 '+'만으로 설정되지 않아야 한다.",
     "① 각 사용자 홈 디렉토리의 .rhosts 파일 확인\n② /etc/hosts.equiv 파일 확인\n③ '+' 설정 여부 확인",
     "양호: .rhosts 및 hosts.equiv 파일 없거나 '+' 설정 없음\n취약: '+' 설정 존재 또는 임의 호스트 허용",
     "상",
     "+ +,+",
     "파일 없음"),

    ("U-18", "접속 IP 및 포트 제한", "서비스관리",
     "TCP Wrapper 또는 방화벽을 이용하여 불필요한 접속을 제한해야 한다.",
     "① /etc/hosts.allow, /etc/hosts.deny 파일 확인\n② iptables 또는 방화벽 설정 확인",
     "양호: 접속 IP/포트 제한 설정 존재\n취약: 접속 제한 정책 없음",
     "상",
     "allow all,deny 없음",
     "hosts.deny,iptables,firewall"),

    ("U-19", "Finger 서비스 비활성화", "서비스관리",
     "Finger 서비스가 비활성화되어야 한다.",
     "① /etc/inetd.conf 또는 /etc/xinetd.d/finger 파일 확인\n② finger 서비스 활성화 여부 확인",
     "양호: finger 서비스 비활성화 또는 미설치\n취약: finger 서비스 활성화",
     "상",
     "finger 활성화,finger enable",
     "disable,미설치,NOT_INSTALLED"),

    ("U-20", "Anonymous FTP 비활성화", "서비스관리",
     "Anonymous(익명) FTP 접속이 허용되지 않아야 한다.",
     "① FTP 설정 파일(/etc/vsftpd.conf 등) 확인\n② anonymous_enable 설정 확인",
     "양호: anonymous_enable=NO 또는 FTP 미사용\n취약: anonymous_enable=YES",
     "상",
     "anonymous_enable=yes",
     "anonymous_enable=no,NOT_INSTALLED"),

    ("U-21", "r 계열 서비스 비활성화", "서비스관리",
     "rsh, rlogin, rexec 등 r 계열 서비스가 비활성화되어야 한다.",
     "① /etc/inetd.conf 또는 /etc/xinetd.d/ 디렉토리 확인\n② rsh, rlogin, rexec 서비스 활성화 여부 확인",
     "양호: r 계열 서비스 비활성화 또는 미설치\n취약: r 계열 서비스 활성화",
     "상",
     "rsh enable,rlogin enable,rexec enable",
     "disable,NOT_INSTALLED"),

    ("U-22", "cron 파일 소유자 및 권한 설정", "서비스관리",
     "cron 관련 파일의 소유자와 권한이 적절히 설정되어야 한다.",
     "① /etc/crontab, /var/spool/cron 권한 확인\n② cron 관련 파일 소유자 확인",
     "양호: cron 파일 소유자 root, 적절한 권한 설정\n취약: 일반 사용자가 cron 파일 수정 가능",
     "상",
     "world writable cron",
     "root,600,640"),

    ("U-23", "DoS 공격에 취약한 서비스 비활성화", "서비스관리",
     "echo, discard, daytime, chargen 등 DoS 공격에 악용될 수 있는 서비스가 비활성화되어야 한다.",
     "① /etc/inetd.conf 또는 /etc/xinetd.d/ 확인\n② echo, discard, daytime, chargen 서비스 활성화 여부",
     "양호: 해당 서비스 비활성화\n취약: 해당 서비스 활성화",
     "상",
     "echo enable,chargen enable,daytime enable",
     "disable,NOT_INSTALLED"),

    ("U-24", "NFS 서비스 비활성화", "서비스관리",
     "불필요한 NFS(Network File System) 서비스가 비활성화되어야 한다.",
     "① NFS 서비스 동작 여부 확인\n② /etc/exports 파일 확인",
     "양호: NFS 서비스 미사용 또는 필요한 경우 접근 제한 설정\n취약: NFS 서비스 사용 중이며 접근 제한 없음",
     "중",
     "*(rw),*(ro) 무제한",
     "NOT_INSTALLED,no_root_squash 없음"),

    ("U-25", "NFS 접근 통제", "서비스관리",
     "NFS 사용 시 everyone 또는 world 접근을 허용하지 않아야 한다.",
     "① /etc/exports 파일에서 공유 설정 확인\n② 접근 허용 호스트 설정 확인",
     "양호: 특정 호스트만 접근 허용\n취약: *(모든 호스트) 접근 허용",
     "상",
     "*(rw),*(ro)",
     "특정 IP,특정 호스트"),

    ("U-26", "automount 비활성화", "서비스관리",
     "불필요한 automount 서비스가 비활성화되어야 한다.",
     "① automount 서비스 동작 여부 확인",
     "양호: automount 서비스 미사용\n취약: automount 서비스 활성화",
     "하",
     "automount active",
     "inactive,NOT_INSTALLED"),

    ("U-27", "RPC 서비스 확인", "서비스관리",
     "불필요한 RPC 서비스가 비활성화되어야 한다.",
     "① rpcinfo 명령으로 실행 중인 RPC 서비스 확인\n② 불필요한 서비스 존재 여부 확인",
     "양호: 필요한 RPC 서비스만 실행\n취약: 불필요한 RPC 서비스 실행",
     "중",
     "rpc 불필요 서비스",
     "NOT_INSTALLED"),

    ("U-28", "NIS, NIS+ 점검", "서비스관리",
     "불필요한 NIS/NIS+ 서비스가 비활성화되어야 한다.",
     "① ypbind, ypserv 서비스 동작 여부 확인",
     "양호: NIS/NIS+ 서비스 미사용\n취약: NIS/NIS+ 서비스 활성화",
     "상",
     "ypbind active,ypserv active",
     "inactive,NOT_INSTALLED"),

    ("U-29", "tftp, talk 서비스 비활성화", "서비스관리",
     "tftp, talk, ntalk 서비스가 비활성화되어야 한다.",
     "① /etc/inetd.conf 또는 /etc/xinetd.d/ 확인\n② tftp, talk 서비스 활성화 여부 확인",
     "양호: tftp, talk 서비스 비활성화\n취약: 해당 서비스 활성화",
     "상",
     "tftp enable,talk enable",
     "disable,NOT_INSTALLED"),

    ("U-30", "Sendmail 버전 점검", "서비스관리",
     "Sendmail을 사용하는 경우 최신 버전을 사용하고 있어야 한다.",
     "① sendmail 버전 확인\n② 알려진 취약점 버전 여부 확인",
     "양호: 최신 패치 적용된 버전 사용\n취약: 취약점이 있는 구버전 사용",
     "중",
     "sendmail 구버전",
     "최신버전,NOT_INSTALLED"),

    ("U-31", "스팸 메일 릴레이 제한", "서비스관리",
     "메일 서버가 스팸 메일 릴레이로 악용되지 않도록 설정해야 한다.",
     "① /etc/mail/sendmail.cf 또는 main.cf 파일 확인\n② 릴레이 설정 확인",
     "양호: 릴레이 제한 설정(자신의 도메인만 허용)\n취약: 모든 메일 릴레이 허용",
     "상",
     "relay 무제한,allow relay all",
     "relay 제한,NOT_INSTALLED"),

    ("U-32", "일반사용자의 Sendmail 실행 방지", "서비스관리",
     "Sendmail이 root 권한으로만 실행되어야 한다.",
     "① Sendmail 실행 권한 및 소유자 확인\n② SUID 설정 여부 확인",
     "양호: Sendmail SUID 미설정\n취약: 일반 사용자가 sendmail 직접 실행 가능",
     "중",
     "sendmail suid",
     "NOT_INSTALLED,suid 없음"),

    ("U-33", "DNS 보안 버전 패치", "서비스관리",
     "DNS 서비스 사용 시 최신 버전을 사용해야 한다.",
     "① named 버전 확인\n② 알려진 취약점 버전 여부 확인",
     "양호: 최신 패치된 버전\n취약: 취약점 있는 구버전",
     "상",
     "bind 구버전,named 구버전",
     "NOT_INSTALLED,최신버전"),

    ("U-34", "DNS Zone Transfer 설정", "서비스관리",
     "DNS Zone Transfer가 허가된 사용자에게만 허용되어야 한다.",
     "① /etc/named.conf 파일의 allow-transfer 설정 확인",
     "양호: 특정 슬레이브 서버만 Zone Transfer 허용\n취약: 모든 호스트에 Zone Transfer 허용",
     "상",
     "allow-transfer { any",
     "allow-transfer 제한,NOT_INSTALLED"),

    ("U-35", "웹서비스 디렉토리 리스팅 제한", "서비스관리",
     "웹 서버의 디렉토리 리스팅이 비활성화되어야 한다.",
     "① Apache: httpd.conf의 Options Indexes 확인\n② Nginx: autoindex 설정 확인",
     "양호: 디렉토리 리스팅 비활성화\n취약: Options Indexes 또는 autoindex on",
     "중",
     "options indexes,autoindex on",
     "options -indexes,autoindex off,NOT_INSTALLED"),

    ("U-36", "웹서비스 웹 프로세스 권한 제한", "서비스관리",
     "웹 서버 프로세스가 root 권한으로 실행되지 않아야 한다.",
     "① 웹 서버 실행 계정 확인\n② httpd.conf의 User/Group 설정 확인",
     "양호: nobody, apache, www 등 일반 계정으로 실행\n취약: root 계정으로 실행",
     "상",
     "user root,group root",
     "user nobody,user apache,user www,NOT_INSTALLED"),

    ("U-37", "웹서비스 상위 디렉토리 접근 제한", "서비스관리",
     "웹 서비스에서 상위 디렉토리(../)로 접근이 불가능해야 한다.",
     "① AllowOverride, Directory 설정 확인\n② 상위 디렉토리 접근 제한 설정 여부",
     "양호: 상위 디렉토리 접근 제한 설정\n취약: 상위 디렉토리 접근 허용",
     "중",
     "allowoverride all 무제한",
     "allowoverride none,NOT_INSTALLED"),

    ("U-38", "웹서비스 불필요한 파일 제거", "서비스관리",
     "웹 서버의 불필요한 기본 파일, 예제 파일이 제거되어야 한다.",
     "① 기본 설치 예제 파일 존재 여부 확인\n② /var/www/html 또는 DocumentRoot 확인",
     "양호: 불필요한 기본 파일 제거됨\n취약: 기본 예제 파일 존재",
     "중",
     "manual,examples,test.html",
     ""),

    ("U-39", "웹서비스 링크 사용 금지", "서비스관리",
     "웹 서버에서 심볼릭 링크를 통한 접근이 제한되어야 한다.",
     "① httpd.conf의 FollowSymLinks 설정 확인",
     "양호: FollowSymLinks 비활성화\n취약: FollowSymLinks 활성화",
     "중",
     "followsymlinks",
     "NOT_INSTALLED"),

    ("U-40", "웹서비스 파일 업로드 및 다운로드 제한", "서비스관리",
     "웹 서비스에서 파일 업로드 크기 및 실행 가능 파일 업로드가 제한되어야 한다.",
     "① 파일 업로드 크기 제한 설정 확인\n② 업로드 디렉토리 실행 권한 확인",
     "양호: 업로드 크기 제한 및 실행 불가 설정\n취약: 무제한 업로드 허용",
     "중",
     "upload 무제한",
     "LimitRequestBody,client_max_body_size"),

    ("U-41", "웹서비스 게시판 SQL 인젝션 차단", "서비스관리",
     "웹 서비스에서 SQL 인젝션 공격을 차단하는 필터링이 적용되어야 한다.",
     "① 입력값 검증 로직 확인\n② WAF 또는 mod_security 설정 확인",
     "양호: SQL 인젝션 필터링 적용\n취약: 입력값 필터링 없음",
     "상",
     "필터링 없음",
     "mod_security,waf"),

    ("U-42", "최신 보안패치 및 벤더 권고사항 적용", "패치관리",
     "운영체제 및 주요 소프트웨어의 최신 보안 패치가 적용되어야 한다.",
     "① 운영체제 패치 현황 확인\n② 주요 소프트웨어 버전 확인",
     "양호: 최신 보안 패치 적용\n취약: 보안 패치 미적용",
     "상",
     "패치 미적용,구버전",
     "최신버전,업데이트됨"),

    ("U-43", "로그온 시 경고 메시지 제공", "로그관리",
     "시스템 로그온 시 보안 경고 메시지(배너)가 표시되어야 한다.",
     "① /etc/motd 파일 내용 확인\n② /etc/issue, /etc/issue.net 파일 확인\n③ SSH banner 설정 확인",
     "양호: 보안 경고 메시지 설정됨\n취약: 경고 메시지 없거나 시스템 정보 노출",
     "하",
     "시스템 정보 노출,banner 없음",
     "경고,authorized,warning"),

    ("U-44", "NTP 서비스 활성화", "로그관리",
     "시스템 시간 동기화를 위해 NTP 서비스가 활성화되어야 한다.",
     "① NTP 서비스 동작 여부 확인\n② /etc/ntp.conf 또는 chrony 설정 확인",
     "양호: NTP 서비스 활성화 및 동기화 정상\n취약: NTP 서비스 미사용",
     "하",
     "ntp inactive,ntp NOT_INSTALLED",
     "ntp active,chronyd active"),

    ("U-45", "로그의 정기적 검토 및 보고", "로그관리",
     "시스템 로그가 정기적으로 검토되고 보관되어야 한다.",
     "① 로그 보관 정책 확인\n② /etc/logrotate.conf 설정 확인",
     "양호: 로그 보관 정책 설정 및 정기 검토\n취약: 로그 보관 정책 없음",
     "중",
     "logrotate 없음",
     "logrotate,rotate"),

    ("U-46", "syslog 설정", "로그관리",
     "시스템 주요 이벤트가 syslog에 기록되도록 설정되어야 한다.",
     "① /etc/syslog.conf 또는 /etc/rsyslog.conf 확인\n② 주요 facility/severity 로깅 여부 확인",
     "양호: auth, kern 등 주요 로그 설정됨\n취약: 로그 설정 없거나 미흡",
     "중",
     "로그 설정 없음",
     "auth,kern,*.info"),

    ("U-47", "로그온 실패 로깅", "로그관리",
     "로그인 실패 시도가 로그에 기록되어야 한다.",
     "① /var/log/auth.log 또는 /var/log/secure 파일 확인\n② 로그인 실패 이벤트 기록 여부 확인",
     "양호: 로그인 실패 기록됨\n취약: 로그인 실패 기록 없음",
     "중",
     "auth 로그 없음",
     "auth.log,secure"),

    ("U-48", "su 명령어 제한", "계정관리",
     "su 명령어 사용이 wheel 그룹 등 허가된 사용자로 제한되어야 한다.",
     "① /etc/pam.d/su 파일의 pam_wheel.so 설정 확인\n② wheel 그룹 설정 확인",
     "양호: su 명령어 wheel 그룹으로 제한\n취약: 모든 사용자 su 사용 가능",
     "중",
     "pam_wheel 없음",
     "pam_wheel.so,wheel"),

    ("U-49", "계정관리 정책 수립", "계정관리",
     "패스워드 최대 사용 기간, 최소 사용 기간, 만료 경고 정책이 설정되어야 한다.",
     "① /etc/login.defs 파일의 PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE 확인",
     "양호: PASS_MAX_DAYS 90 이하, 적절한 패스워드 정책 설정\n취약: 패스워드 만료 정책 미설정",
     "중",
     "pass_max_days 99999,pass_max_days 없음",
     "pass_max_days 90,pass_max_days 60"),

    ("U-50", "세션 타임아웃 설정", "계정관리",
     "일정 시간 동안 활동이 없는 세션은 자동으로 종료되어야 한다.",
     "① /etc/profile 또는 /etc/bashrc의 TMOUT 설정 확인\n② SSH ClientAliveInterval 설정 확인",
     "양호: TMOUT 300(5분) 이하 또는 ClientAliveInterval 설정\n취약: 세션 타임아웃 미설정",
     "중",
     "tmout 없음,clientaliveinterval 없음",
     "tmout,clientaliveinterval"),

    # U-51 ~ U-72 간략 버전
    ("U-51", "hosts.equiv 파일 설정", "서비스관리",
     "/etc/hosts.equiv 파일이 적절히 설정되어야 한다.",
     "① /etc/hosts.equiv 파일 내용 확인\n② '+' 설정 여부 확인",
     "양호: hosts.equiv 파일 없거나 '+' 없음\n취약: '+' 설정으로 모든 호스트 신뢰",
     "상", "+ 설정", "파일 없음"),

    ("U-52", "SNMP 서비스 비활성화", "서비스관리",
     "SNMP 서비스 미사용 시 비활성화해야 한다.",
     "① SNMP 서비스 동작 여부 확인\n② community string 설정 확인",
     "양호: SNMP 미사용 또는 community string 변경\n취약: 기본 community string(public/private) 사용",
     "상", "community public,community private", "NOT_INSTALLED,변경된 문자열"),

    ("U-53", "SNMP community string 복잡성 설정", "서비스관리",
     "SNMP community string이 추측하기 어렵게 설정되어야 한다.",
     "① /etc/snmp/snmpd.conf 파일 확인\n② community string 복잡성 확인",
     "양호: 복잡한 community string 설정\n취약: public, private 등 기본값 사용",
     "상", "community public,community private", "복잡한 문자열"),

    ("U-54", "FTP 서비스 잠금 계정 설정", "서비스관리",
     "FTP 접속 시 시스템 계정으로의 접근이 제한되어야 한다.",
     "① /etc/ftpusers 또는 /etc/vsftpd/ftpusers 파일 확인\n② root 계정 FTP 접근 제한 여부 확인",
     "양호: root 등 시스템 계정 FTP 차단\n취약: 모든 계정 FTP 접근 허용",
     "중", "root ftp 허용", "ftpusers,root 차단"),

    ("U-55", "FTP 서비스 비활성화", "서비스관리",
     "FTP 서비스를 사용하지 않는 경우 비활성화해야 한다.",
     "① FTP 서비스 동작 여부 확인",
     "양호: FTP 미사용 또는 SFTP로 대체\n취약: 불필요한 FTP 서비스 활성화",
     "상", "ftp active,ftp RUNNING", "NOT_INSTALLED,inactive"),

    ("U-56", "FTP 계정 shell 제한", "서비스관리",
     "FTP 전용 계정에 일반 shell이 부여되지 않아야 한다.",
     "① FTP 계정의 /etc/passwd shell 필드 확인",
     "양호: FTP 계정에 /sbin/nologin 또는 /bin/false 설정\n취약: FTP 계정에 일반 shell 부여",
     "중", "ftp:/bin/bash,ftp:/bin/sh", "nologin,false"),

    ("U-57", "Linuxd 서비스 관리", "서비스관리",
     "불필요한 서비스가 xinetd를 통해 실행되지 않아야 한다.",
     "① /etc/xinetd.d/ 디렉토리 내 파일 확인\n② 불필요한 서비스 활성화 여부",
     "양호: 불필요한 서비스 비활성화\n취약: 불필요한 서비스 xinetd를 통해 실행",
     "중", "disable = no 불필요 서비스", "disable = yes"),

    ("U-58", "Sendmail 서비스 관리", "서비스관리",
     "Sendmail 서비스를 사용하지 않는 경우 비활성화해야 한다.",
     "① Sendmail 서비스 동작 여부 확인",
     "양호: Sendmail 미사용 또는 비활성화\n취약: 불필요한 Sendmail 서비스 활성화",
     "중", "sendmail active", "NOT_INSTALLED,inactive"),

    ("U-59", "스크린세이버 보호 설정", "계정관리",
     "일정 시간 이상 미사용 시 스크린세이버와 패스워드 잠금이 활성화되어야 한다.",
     "① 스크린세이버 설정 확인\n② 잠금 화면 설정 확인",
     "양호: 스크린세이버 및 잠금 설정 활성화\n취약: 스크린세이버 미설정",
     "하", "스크린세이버 없음", "screensaver,lock"),

    ("U-60", "SSH 프로토콜 버전 설정", "서비스관리",
     "SSH 버전 2만 사용해야 한다.",
     "① /etc/ssh/sshd_config의 Protocol 설정 확인",
     "양호: Protocol 2 설정\n취약: Protocol 1 허용",
     "상", "protocol 1", "protocol 2"),

    ("U-61", "SSH 서비스 포트 변경", "서비스관리",
     "SSH 서비스 기본 포트(22)를 변경하는 것이 권장된다.",
     "① /etc/ssh/sshd_config의 Port 설정 확인",
     "양호: 기본 포트(22)에서 변경됨\n취약: 기본 포트(22) 사용",
     "하", "port 22", "port 다른번호"),

    ("U-62", "FTP 배너 제거", "서비스관리",
     "FTP 서비스 배너에서 서비스 버전 정보가 노출되지 않아야 한다.",
     "① FTP 배너 설정 확인",
     "양호: 버전 정보 미노출\n취약: FTP 버전 정보 배너에 노출",
     "하", "버전 노출", "banner 변경,NOT_INSTALLED"),

    ("U-63", "웹서비스 서버 정보 노출 방지", "서비스관리",
     "웹 서버 응답 헤더에서 서버 버전 정보가 노출되지 않아야 한다.",
     "① httpd.conf의 ServerTokens 설정 확인\n② ServerSignature 설정 확인",
     "양호: ServerTokens Prod, ServerSignature Off\n취약: 버전 정보 노출",
     "중", "servertokens full,servertokens os", "servertokens prod,NOT_INSTALLED"),

    ("U-64", "WebDAV 비활성화", "서비스관리",
     "WebDAV가 사용되지 않는 경우 비활성화해야 한다.",
     "① Apache mod_dav 모듈 로드 여부 확인",
     "양호: WebDAV 비활성화\n취약: WebDAV 활성화",
     "중", "dav on,mod_dav", "NOT_INSTALLED,dav off"),

    ("U-65", "WAS 취약점 점검", "서비스관리",
     "WAS(Web Application Server) 보안 설정이 적절히 되어야 한다.",
     "① 관리자 페이지 접근 제한 확인\n② 기본 계정 변경 여부 확인",
     "양호: 관리자 페이지 IP 제한, 기본 계정 변경\n취약: 관리자 페이지 무제한 접근",
     "상", "admin 무제한,기본계정", "ip 제한,계정 변경"),

    ("U-66", "디버그 옵션 비활성화", "서비스관리",
     "운영 환경에서 디버그 모드가 비활성화되어야 한다.",
     "① 서비스 설정 파일의 debug 옵션 확인",
     "양호: 디버그 모드 비활성화\n취약: 디버그 모드 활성화",
     "중", "debug=true,debug on,debug_mode=1", "debug=false,debug off"),

    ("U-67", "Tomcat 관리자 페이지 접근 제한", "서비스관리",
     "Tomcat 관리자 페이지에 대한 접근이 제한되어야 한다.",
     "① tomcat-users.xml 파일 확인\n② manager 애플리케이션 접근 제한 확인",
     "양호: 관리자 페이지 IP 제한 또는 비활성화\n취약: 관리자 페이지 무제한 접근",
     "상", "allow 0.0.0.0/0,모든 IP", "NOT_INSTALLED,ip 제한"),

    ("U-68", "MySQL root 계정 원격접속 제한", "서비스관리",
     "MySQL root 계정의 원격 접속이 제한되어야 한다.",
     "① MySQL user 테이블의 root 계정 host 설정 확인",
     "양호: root 계정 localhost만 접속 허용\n취약: root 계정 원격 접속 허용",
     "상", "root '%',root 원격", "root localhost,NOT_INSTALLED"),

    ("U-69", "MySQL 일반 계정 원격접속 제한", "서비스관리",
     "MySQL 일반 계정의 불필요한 원격 접속이 제한되어야 한다.",
     "① MySQL user 테이블 확인\n② 불필요한 원격 접속 허용 계정 확인",
     "양호: 필요한 계정만 원격 접속 허용\n취약: 불필요한 계정 원격 접속 허용",
     "중", "% 모든 호스트", "localhost,특정 IP"),

    ("U-70", "MySQL 데이터베이스 파일 권한 설정", "서비스관리",
     "MySQL 데이터베이스 파일의 소유자와 권한이 적절히 설정되어야 한다.",
     "① /var/lib/mysql 또는 데이터 디렉토리 권한 확인",
     "양호: mysql 계정 소유, 700 이하 권한\n취약: 타 사용자 접근 가능",
     "중", "world readable,777", "700,mysql 소유"),

    ("U-71", "MySQL 로그 설정", "로그관리",
     "MySQL 로그(일반 로그, 오류 로그, 바이너리 로그)가 활성화되어야 한다.",
     "① /etc/mysql/my.cnf 또는 my.ini 파일 확인\n② log 설정 확인",
     "양호: 주요 로그 설정 활성화\n취약: 로그 설정 없음",
     "중", "로그 없음", "general_log,error_log,binlog"),

    ("U-72", "SSL/TLS 설정", "서비스관리",
     "SSL/TLS 프로토콜이 최신 안전한 버전으로 설정되어야 한다.",
     "① SSL/TLS 프로토콜 버전 확인\n② 취약한 암호화 알고리즘 사용 여부 확인",
     "양호: TLS 1.2 이상 사용, 취약 알고리즘 비사용\n취약: SSLv2, SSLv3, TLS 1.0 사용",
     "상", "sslv2,sslv3,tlsv1.0,sslprotocol -all +sslv2", "tlsv1.2,tlsv1.3"),
]

# ──────────────────────────────────────────────────────────────
# DB 생성 및 데이터 삽입
# ──────────────────────────────────────────────────────────────

conn = sqlite3.connect(DB_PATH)
conn.execute("""
CREATE TABLE IF NOT EXISTS guidelines (
    item_code    TEXT PRIMARY KEY,
    item_name    TEXT,
    category     TEXT,
    content      TEXT,
    check_point  TEXT,
    standard     TEXT,
    severity     TEXT,
    vuln_keywords  TEXT,
    ok_keywords    TEXT
)
""")

conn.executemany("""
INSERT OR REPLACE INTO guidelines
    (item_code, item_name, category, content, check_point, standard, severity, vuln_keywords, ok_keywords)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
""", GUIDELINES)

conn.commit()
count = conn.execute("SELECT COUNT(*) FROM guidelines").fetchone()[0]
conn.close()

print(f"[Seed] guidelines DB 생성 완료: {count}건 저장 → {DB_PATH}")
