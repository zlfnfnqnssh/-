#!/usr/bin/env bash
# ============================================================
#  주통기 취약점 자동 진단 시스템 - 원클릭 런처 (Linux / macOS / WSL)
# ============================================================
#  실행: chmod +x start_server.sh && ./start_server.sh
#  - Python 3.10+ / Docker 가 설치돼 있어야 함 (없으면 안내 메시지만)
#  - 처음 실행 시 venv 생성 + 의존성 설치 (5~10분 소요)
#  - 이후 실행은 venv 재사용 + 서버 기동 + 브라우저 자동 오픈
# ============================================================

set -u   # set -e 는 의도된 errorlevel 분기 때문에 안 씀

# ── 색깔 (TTY 일 때만) ─────────────────────────────────────
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    BOLD="$(tput bold)"; DIM="$(tput dim)"; RST="$(tput sgr0)"
    RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
else
    BOLD=""; DIM=""; RST=""; RED=""; GREEN=""; YELLOW=""
fi
say()  { printf "%s\n" "$*"; }
ok()   { printf "${GREEN}%s${RST}\n" "$*"; }
warn() { printf "${YELLOW}%s${RST}\n" "$*"; }
err()  { printf "${RED}%s${RST}\n" "$*" >&2; }

# ── 위치 ──────────────────────────────────────────────────
ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
APP_DIR="$ROOT_DIR/vulnerability-scanner"
VENV_DIR="$ROOT_DIR/.venv"
DEPS_MARKER="$ROOT_DIR/.deps_installed"
PID_FILE="$ROOT_DIR/.server.pid"
LOG_FILE="$ROOT_DIR/server.log"

if [ ! -d "$APP_DIR" ]; then
    err "[ERROR] vulnerability-scanner 디렉토리를 찾을 수 없음: $APP_DIR"
    exit 1
fi

cd "$APP_DIR"

say "============================================================"
say "${BOLD} 주통기 취약점 진단 시스템 - 원클릭 런처 (Linux/macOS)${RST}"
say "============================================================"
say ""

# ── 1. 배포판 감지 (안내용) ────────────────────────────────
DISTRO="unknown"
PKG_HINT=""
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    case "$DISTRO" in
        ubuntu|debian|raspbian|linuxmint|pop)
            PKG_HINT="sudo apt-get install -y python3 python3-venv python3-pip docker.io docker-compose-plugin" ;;
        rhel|centos|fedora|rocky|almalinux)
            PKG_HINT="sudo dnf install -y python3 python3-pip docker docker-compose-plugin" ;;
        arch|manjaro|endeavouros)
            PKG_HINT="sudo pacman -S --needed python python-pip docker docker-compose" ;;
        alpine)
            PKG_HINT="sudo apk add python3 py3-pip py3-virtualenv docker docker-cli-compose" ;;
        opensuse*|sles)
            PKG_HINT="sudo zypper install -y python3 python3-pip docker docker-compose" ;;
    esac
elif [ "$(uname -s)" = "Darwin" ]; then
    DISTRO="macos"
    PKG_HINT="brew install python@3.11 docker docker-compose   (Docker Desktop 권장)"
fi
say "[0/6] 환경: ${BOLD}$DISTRO${RST}"
say ""

# ── 2. Python 확인 (3.10+) ────────────────────────────────
PY=""
for cand in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        ver="$("$cand" -c 'import sys; print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "")"
        major="${ver%.*}"; minor="${ver#*.}"
        if [ "$major" = "3" ] && [ "${minor:-0}" -ge 10 ] 2>/dev/null; then
            PY="$cand"; PYVER="$ver"; break
        fi
    fi
done
if [ -z "$PY" ]; then
    err "[ERROR] Python 3.10+ 을 찾을 수 없음."
    [ -n "$PKG_HINT" ] && say "        설치 안내: $PKG_HINT"
    say "        또는: https://www.python.org/downloads/"
    exit 1
fi
say "[1/6] Python: ${BOLD}$PY (v$PYVER)${RST}"

# ── 3. venv 생성 + 의존성 설치 (마커로 한 번만) ─────────────
if [ ! -d "$VENV_DIR" ]; then
    say "[2/6] venv 생성 중... ($VENV_DIR)"
    if ! "$PY" -m venv "$VENV_DIR" 2>/dev/null; then
        err "[ERROR] venv 생성 실패."
        case "$DISTRO" in
            ubuntu|debian|raspbian|linuxmint|pop)
                say "        Ubuntu/Debian: sudo apt-get install -y python3-venv" ;;
            *)
                [ -n "$PKG_HINT" ] && say "        설치 안내: $PKG_HINT" ;;
        esac
        exit 1
    fi
fi
# shellcheck source=/dev/null
. "$VENV_DIR/bin/activate"

if [ ! -f "$DEPS_MARKER" ]; then
    say "[2/6] 의존성 설치 중... (5~10분 소요, 처음 한 번만)"
    python -m pip install --upgrade pip --quiet
    if ! python -m pip install -r requirements.txt; then
        err "[ERROR] 의존성 설치 실패. requirements.txt 확인."
        exit 1
    fi
    : > "$DEPS_MARKER"
    ok "      의존성 설치 완료"
else
    say "[2/6] 의존성: ${DIM}이미 설치됨 (.deps_installed 마커)${RST}"
fi

# ── 4. Docker 확인 / 자동 설치 / 자동 기동 ─────────────────
say "[3/6] Docker 환경 확인..."

# 4-1. Docker 명령 자체가 없으면 자동 설치 시도
ask_yn() {
    # $1=prompt, returns 0 if yes
    local prompt="$1" ans
    if [ ! -t 0 ]; then return 1; fi   # 비대화형이면 자동 NO
    printf "%s [y/N] " "$prompt"
    read -r ans
    case "$ans" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

install_docker_linux() {
    # 배포판별 Docker 설치 (sudo 필요)
    case "$DISTRO" in
        ubuntu|debian|raspbian|linuxmint|pop)
            sudo apt-get update -qq && \
            sudo apt-get install -y docker.io docker-compose-plugin
            ;;
        fedora|rhel|centos|rocky|almalinux)
            sudo dnf install -y docker docker-compose-plugin && \
            sudo systemctl enable --now docker
            ;;
        arch|manjaro|endeavouros)
            sudo pacman -S --needed --noconfirm docker docker-compose && \
            sudo systemctl enable --now docker
            ;;
        alpine)
            sudo apk add --no-cache docker docker-cli-compose && \
            sudo rc-update add docker default && sudo service docker start
            ;;
        opensuse*|sles)
            sudo zypper install -y docker docker-compose && \
            sudo systemctl enable --now docker
            ;;
        *)
            err "      [ERROR] 지원되지 않는 배포판($DISTRO). 수동 설치 필요:"
            say "             https://docs.docker.com/engine/install/"
            return 1
            ;;
    esac
}

install_docker_macos() {
    if command -v brew >/dev/null 2>&1; then
        say "      brew 로 Docker Desktop (cask) 설치..."
        brew install --cask docker
    else
        err "      [ERROR] Homebrew 가 없음. 수동 설치 필요:"
        say "             https://www.docker.com/products/docker-desktop/"
        return 1
    fi
}

if ! command -v docker >/dev/null 2>&1; then
    warn "      Docker 가 설치되지 않음."
    if ask_yn "      자동으로 설치할까요? (sudo 권한 필요)"; then
        if [ "$DISTRO" = "macos" ]; then
            install_docker_macos || exit 1
        else
            install_docker_linux || exit 1
        fi
        ok "      Docker 설치 완료."
        # 설치 직후 PATH/그룹 새로고침이 필요할 수 있음
        if [ "$DISTRO" != "macos" ] && ! groups 2>/dev/null | grep -qw docker; then
            say "      현재 사용자를 docker 그룹에 추가 (재로그인 필요)..."
            sudo usermod -aG docker "$USER" || true
            warn "      [중요] docker 그룹 권한 적용을 위해 ${BOLD}로그아웃 후 다시 로그인${RST}하거나"
            warn "             ${BOLD}newgrp docker${RST} 실행 후 이 스크립트를 재실행하세요."
            exit 0
        fi
    else
        [ -n "$PKG_HINT" ] && say "      설치 안내: $PKG_HINT"
        say "      또는: https://docs.docker.com/engine/install/"
        exit 1
    fi
fi

# 4-2. Docker daemon 응답 확인 + 자동 기동
if ! docker info >/dev/null 2>&1; then
    warn "      Docker 데몬이 실행 중이 아님. 자동 기동 시도..."
    if [ "$(uname -s)" = "Darwin" ]; then
        # macOS: Docker Desktop 실행
        open -a Docker 2>/dev/null || open -a "Docker Desktop" 2>/dev/null || true
    elif command -v systemctl >/dev/null 2>&1; then
        sudo systemctl start docker 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        sudo service docker start 2>/dev/null || true
    fi
    # 데몬 준비 대기 (최대 90초)
    say "      Docker daemon 준비 대기 (최대 90초)..."
    DOCKER_READY=0
    for i in $(seq 1 30); do
        sleep 3
        if docker info >/dev/null 2>&1; then
            ok "      Docker daemon 준비 완료 (약 $((i*3))초)"
            DOCKER_READY=1
            break
        fi
    done
    if [ "$DOCKER_READY" -ne 1 ]; then
        err "      [ERROR] Docker daemon 90초 내 응답 없음."
        if [ "$DISTRO" = "macos" ]; then
            say "             Docker Desktop 첫 실행 시 라이선스 동의 필요할 수 있음."
        else
            say "             sudo systemctl status docker 로 상태 확인."
        fi
        exit 1
    fi
fi

# 4-3. postgres-db 컨테이너 확인 / 기동
# 주의: docker-compose.yml 서비스명은 "postgres" (컨테이너명만 "postgres-db")
PG_STARTED=0
if docker ps --filter "name=postgres-db" --format '{{.Names}}' 2>/dev/null | grep -q "^postgres-db$"; then
    ok "      postgres-db 실행 중"
    PG_STARTED=1
elif docker ps -a --filter "name=postgres-db" --format '{{.Names}}' 2>/dev/null | grep -q "^postgres-db$"; then
    say "      postgres-db 컨테이너 stopped → 재시작..."
    if docker start postgres-db >/dev/null 2>&1; then
        ok "      postgres-db 재시작 완료"
        PG_STARTED=1
    fi
fi

if [ "$PG_STARTED" -ne 1 ]; then
    say "      postgres-db 컨테이너 없음. Docker Compose 로 신규 생성..."
    if docker compose version >/dev/null 2>&1; then
        DC_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        DC_CMD="docker-compose"
    else
        DC_CMD=""
    fi
    if [ -n "$DC_CMD" ] && [ -f "$ROOT_DIR/docker-compose.yml" ]; then
        if $DC_CMD -f "$ROOT_DIR/docker-compose.yml" up -d postgres; then
            ok "      postgres-db 기동 완료 ($DC_CMD)"
            PG_STARTED=1
        else
            warn "      [WARN] postgres 자동 기동 실패. DB 없이도 서버는 띄울 수 있으나 점검 기능 사용 불가."
        fi
    else
        warn "      [WARN] docker compose / docker-compose 명령을 찾을 수 없음. 수동 기동 필요."
    fi
fi

# postgres ready 폴링 (최대 30초)
if [ "$PG_STARTED" -eq 1 ]; then
    for i in $(seq 1 15); do
        sleep 2
        if docker exec postgres-db pg_isready -U postgres >/dev/null 2>&1; then
            ok "      postgres ready (약 $((i*2))초)"
            break
        fi
    done
fi

# ── 5. .env 자동 생성 ──────────────────────────────────────
if [ ! -f "$APP_DIR/.env" ]; then
    if [ -f "$APP_DIR/.env.example" ]; then
        cp "$APP_DIR/.env.example" "$APP_DIR/.env"
        ok "[4/6] .env 자동 생성 (.env.example → .env)"
    else
        warn "[4/6] .env / .env.example 둘 다 없음. PG 비밀번호가 기본값일 때만 동작."
    fi
else
    say "[4/6] .env: ${DIM}이미 존재${RST}"
fi

# ── 6. 서버 기동 (background) ──────────────────────────────
# 이미 8081 점유 중이면 스킵
if command -v lsof >/dev/null 2>&1; then
    LISTEN_PID="$(lsof -ti:8081 2>/dev/null | head -n1 || true)"
elif command -v ss >/dev/null 2>&1; then
    LISTEN_PID="$(ss -ltnp 2>/dev/null | awk '/:8081 /{print $7}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -n1)"
else
    LISTEN_PID=""
fi

if [ -n "${LISTEN_PID:-}" ]; then
    warn "[5/6] 8081 포트가 이미 사용 중 (PID=$LISTEN_PID). 기존 서버 그대로 사용."
else
    say "[5/6] 서버 기동 (포트 8081, 로그: $LOG_FILE)..."
    export PYTHONIOENCODING=utf-8
    export PYTHONUTF8=1
    nohup python main.py > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$PID_FILE"
    sleep 5
fi

# ── 7. 동작 확인 + 브라우저 ───────────────────────────────
say "[6/6] 서버 응답 확인..."
URL="http://localhost:8081/login"
HTTP_CODE=""
# 최대 10초 동안 1초씩 polling (서버 startup + DB 초기화 시간 보장)
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if command -v curl >/dev/null 2>&1; then
        HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$URL" 2>/dev/null)"
    elif command -v wget >/dev/null 2>&1; then
        HTTP_CODE="$(wget -q -O /dev/null --server-response "$URL" 2>&1 | awk '/HTTP\//{print $2; exit}')"
    fi
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "303" ] && break
    sleep 1
done

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "303" ]; then
    ok "      서버 응답 정상 (HTTP $HTTP_CODE)"
else
    warn "      [WARN] 서버 응답 비정상 (HTTP ${HTTP_CODE:-?})"
    # 서버 프로세스 확인
    if [ -f "$PID_FILE" ]; then
        SPID="$(cat "$PID_FILE" 2>/dev/null)"
        if [ -n "$SPID" ] && ! kill -0 "$SPID" 2>/dev/null; then
            err "      서버 프로세스가 시작 후 죽음 (PID=$SPID)"
        fi
    fi
    # 마지막 에러 라인 미리보기
    if [ -f "$LOG_FILE" ]; then
        say "      ${DIM}— server.log 마지막 에러 ———————————————${RST}"
        grep -E 'ERROR|Error|Exception|Traceback|Refused|Connect call failed' "$LOG_FILE" | tail -3 | sed 's/^/      /'
        say "      ${DIM}— 전체 로그: tail -f $LOG_FILE ———————${RST}"
    fi
    # WSL 환경 힌트
    if grep -qi microsoft /proc/version 2>/dev/null; then
        say "      ${DIM}WSL 환경에서 PostgreSQL 5432 연결 실패 시:${RST}"
        say "      ${DIM}  → Docker Desktop → Settings → Resources → WSL Integration → 이 distro 토글 ON${RST}"
    fi
fi

# 브라우저 (TTY 환경 + 데스크톱 환경 일 때만)
if [ -t 1 ] && [ -z "${NO_BROWSER:-}" ]; then
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$URL" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$URL" >/dev/null 2>&1 &
    elif command -v wslview >/dev/null 2>&1; then
        # WSL: Windows 호스트 브라우저
        wslview "$URL" >/dev/null 2>&1 &
    fi
fi

say ""
say "============================================================"
ok " 서버 실행 중 — $URL"
say " 로그인:  ${BOLD}admin / admin1234${RST}"
say " 로그:    tail -f $LOG_FILE"
say " 종료:    kill \$(cat $PID_FILE)   (또는 PID: ${SERVER_PID:-$LISTEN_PID})"
say "============================================================"
