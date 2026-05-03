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

# ── 4. Docker 확인 + postgres-db 자동 기동 ─────────────────
say "[3/6] Docker postgres-db 확인..."
if ! command -v docker >/dev/null 2>&1; then
    warn "      [WARN] docker 명령을 찾을 수 없음. 점검 기능 사용 불가 (DB 없음)."
    [ -n "$PKG_HINT" ] && say "             설치 안내: $PKG_HINT"
elif ! docker info >/dev/null 2>&1; then
    warn "      [WARN] Docker 데몬이 실행 중이 아님. (sudo systemctl start docker / Docker Desktop 시작)"
else
    if docker ps --filter "name=postgres-db" --format '{{.Names}}' 2>/dev/null | grep -q "^postgres-db$"; then
        ok "      postgres-db 실행 중"
    else
        say "      postgres-db 컨테이너가 실행 중이 아님. Docker Compose 로 기동 시도..."
        # docker compose v2 → docker-compose v1 fallback
        if docker compose version >/dev/null 2>&1; then
            DC_CMD="docker compose"
        elif command -v docker-compose >/dev/null 2>&1; then
            DC_CMD="docker-compose"
        else
            DC_CMD=""
        fi
        if [ -n "$DC_CMD" ] && [ -f "$ROOT_DIR/docker-compose.yml" ]; then
            if $DC_CMD -f "$ROOT_DIR/docker-compose.yml" up -d postgres-db; then
                ok "      postgres-db 기동 완료 ($DC_CMD)"
                sleep 3
            else
                warn "      [WARN] Docker 자동 기동 실패. DB 없이도 서버는 띄울 수 있으나 점검 기능 사용 불가."
            fi
        else
            warn "      [WARN] docker compose / docker-compose 명령을 찾을 수 없음. 수동 기동 필요."
        fi
    fi
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
