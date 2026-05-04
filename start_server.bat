@echo off
REM ============================================================
REM  주통기 취약점 자동 진단 시스템 - 원클릭 런처 (Windows)
REM ============================================================
REM  실행: 이 파일을 더블클릭하거나 cmd 에서 실행
REM  - Python 3.10+ 와 Docker 가 설치돼 있어야 함
REM  - 처음 실행 시 의존성 자동 설치 (5~10분 소요)
REM  - 이후 실행은 즉시 서버 기동 + 브라우저 자동 오픈
REM ============================================================

setlocal EnableDelayedExpansion
chcp 65001 > nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

cd /d "%~dp0vulnerability-scanner"
if errorlevel 1 (
    echo [ERROR] vulnerability-scanner 디렉토리를 찾을 수 없음.
    pause & exit /b 1
)

echo ============================================================
echo  주통기 취약점 진단 시스템 - 원클릭 런처
echo ============================================================
echo.

REM ── 1. Python 확인 ─────────────────────────────────────────
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python 이 설치되지 않음. https://www.python.org/downloads/ 에서 3.10+ 설치 후 다시 실행.
    pause & exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [1/5] Python 확인: %PYVER%

REM ── 2. 의존성 설치 (markersfile 로 한 번만) ─────────────────
set "DEPS_MARKER=%~dp0.deps_installed"
if not exist "%DEPS_MARKER%" (
    echo [2/5] 의존성 설치 중... (5~10분 소요, 처음 한 번만^)
    python -m pip install --upgrade pip --quiet
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] 의존성 설치 실패. requirements.txt 확인.
        pause & exit /b 1
    )
    echo. > "%DEPS_MARKER%"
    echo       의존성 설치 완료
) else (
    echo [2/5] 의존성: 이미 설치됨 ^(.deps_installed 마커 존재^)
)

REM ── 3. Docker 확인 / 자동 설치 / 자동 기동 ─────────────────
echo [3/5] Docker 환경 확인...

REM 3-1. Docker 명령 자체가 있는지 확인
where docker >nul 2>nul
if errorlevel 1 (
    echo       Docker 가 설치되지 않음.
    REM winget 가능 여부
    where winget >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] winget 도 없음. 수동으로 Docker Desktop 설치 필요:
        echo         https://www.docker.com/products/docker-desktop/
        pause & exit /b 1
    )
    echo       winget 으로 자동 설치 시도 ^(관리자 권한 UAC 창 뜸^)
    echo       다운로드/설치에 5~10분 소요.
    winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo [ERROR] Docker Desktop 설치 실패. 수동 설치 후 다시 실행:
        echo         https://www.docker.com/products/docker-desktop/
        pause & exit /b 1
    )
    echo.
    echo ============================================================
    echo  Docker Desktop 설치 완료!
    echo  ※ 시스템 PATH 반영을 위해 이 창을 닫고 start_server.bat 을
    echo     다시 실행해주세요. ^(첫 실행 시 라이선스 동의 창이 뜰 수 있음^)
    echo ============================================================
    pause & exit /b 0
)

REM 3-2. Docker daemon 응답 확인 (Desktop 미실행 시 재시도)
docker version >nul 2>nul
if not errorlevel 1 goto :docker_ok

echo       Docker Desktop 이 실행 중이 아님. 자동 기동 시도...
REM Program Files 경로 우선 시도, 실패 시 Local AppData
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
    start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
) else if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" (
    start "" "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe"
) else (
    echo [WARN] Docker Desktop.exe 위치를 못 찾음. 수동으로 Docker Desktop 실행 후 재시도.
    pause & exit /b 1
)
echo       Docker daemon 준비 대기 ^(최대 90초^)...
set "_DOCKER_READY="
for /L %%i in (1,1,30) do (
    if not defined _DOCKER_READY (
        timeout /t 3 /nobreak >nul
        docker version >nul 2>nul
        if not errorlevel 1 set "_DOCKER_READY=1"
    )
)
if not defined _DOCKER_READY (
    echo [ERROR] Docker daemon 90초 내 응답 없음. Docker Desktop 수동 확인 필요.
    echo         첫 실행이라면 라이선스 동의 창이 뜨지 않았는지 확인.
    pause & exit /b 1
)
echo       Docker daemon 준비 완료
:docker_ok

REM 3-3. postgres-db 컨테이너 확인 / 기동
REM 주의: docker-compose.yml 의 서비스명은 "postgres" (컨테이너명만 "postgres-db")
docker ps --filter "name=postgres-db" --format "{{.Names}}" 2>nul | findstr /i postgres-db >nul
if not errorlevel 1 (
    echo       postgres-db 실행 중
    goto :pg_done
)

REM 컨테이너가 stopped 상태로 존재? → docker start 로 빠르게 기동
docker ps -a --filter "name=postgres-db" --format "{{.Names}}" 2>nul | findstr /i postgres-db >nul
if not errorlevel 1 (
    echo       postgres-db 컨테이너 stopped → 재시작...
    docker start postgres-db >nul 2>nul
    if not errorlevel 1 (
        echo       postgres-db 재시작 완료
        goto :pg_started
    )
)

echo       postgres-db 컨테이너 없음. Docker Compose 로 신규 생성...
docker compose -f "%~dp0docker-compose.yml" up -d postgres 2>nul
if not errorlevel 1 (
    echo       postgres-db 기동 완료 ^(docker compose v2^)
    goto :pg_started
)
docker-compose -f "%~dp0docker-compose.yml" up -d postgres 2>nul
if not errorlevel 1 (
    echo       postgres-db 기동 완료 ^(docker-compose v1^)
    goto :pg_started
)
echo [WARN] postgres-db 자동 기동 실패. docker-compose.yml 확인 필요.
pause
goto :pg_done

:pg_started
REM postgres ready 폴링 (최대 30초)
echo       postgres ready 대기 ^(최대 30초^)...
set "_PG_READY="
for /L %%i in (1,1,15) do (
    if not defined _PG_READY (
        timeout /t 2 /nobreak >nul
        docker exec postgres-db pg_isready -U postgres >nul 2>nul
        if not errorlevel 1 set "_PG_READY=1"
    )
)
if not defined _PG_READY (
    echo [WARN] postgres 30초 내 ready 안 됨. 서버 시작이 실패하면 잠시 후 재실행.
) else (
    echo       postgres ready
)
:pg_done

REM ── 4. .env 파일 확인 ────────────────────────────────────
if not exist ".env" (
    echo [WARN] .env 파일이 없음. .env.example 을 복사해서 만들거나, 다음 내용을 .env 에 저장:
    echo        PG_HOST=localhost
    echo        PG_PORT=5432
    echo        PG_USER=postgres
    echo        PG_PASSWORD=admin123
    echo        PG_DB=forensic_db
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo       .env.example -^> .env 자동 복사 완료
    )
)

REM ── 5. 서버 기동 + 브라우저 ─────────────────────────────────
echo [4/5] 서버 기동 (포트 8081)...
REM 자식 cmd 에도 UTF-8 + Python UTF-8 모드 전파 (서버 로그 한글 안 깨지게)
REM 주의: cmd /k "..." 안에서 추가 따옴표 쓰면 외부 따옴표가 조기 종료됨 → 따옴표 없이!
REM 주의: set 뒤에 공백+& 두면 환경변수 값에 공백 포함됨 → && 앞뒤 공백 없음 필수
start "주통기 진단 서버" /MIN cmd /k "chcp 65001>nul&&set PYTHONIOENCODING=utf-8&&set PYTHONUTF8=1&&python main.py"

echo [5/5] 서버 시작 대기 (5초)...
timeout /t 5 /nobreak >nul

REM 브라우저 열기
echo       브라우저 열기: http://localhost:8081/login
start "" "http://localhost:8081/login"

echo.
echo ============================================================
echo  서버 실행 중 — http://localhost:8081
echo  로그인: admin / admin1234
echo  종료: 서버 창 닫거나 Ctrl+C
echo ============================================================
echo.
echo 이 창은 닫아도 서버는 계속 실행됩니다.
echo 서버 로그를 보려면 "주통기 진단 서버" 창을 확인하세요.
pause
endlocal
