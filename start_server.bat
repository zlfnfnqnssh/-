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

REM ── 3. Docker 확인 (PostgreSQL forensic_db) ─────────────────
echo [3/5] Docker postgres-db 확인...
docker ps --filter "name=postgres-db" --format "{{.Names}}" 2>nul | findstr /i postgres-db >nul
if errorlevel 1 (
    echo       postgres-db 컨테이너가 실행 중이 아님. Docker Compose 로 기동 시도...
    REM Docker Compose v2 (docker compose) 우선, 실패하면 v1 (docker-compose) fallback
    docker compose -f "%~dp0docker-compose.yml" up -d postgres-db 2>nul
    if errorlevel 1 (
        docker-compose -f "%~dp0docker-compose.yml" up -d postgres-db 2>nul
        if errorlevel 1 (
            echo [WARN] Docker 자동 기동 실패. 수동으로 docker compose up -d 실행 필요.
            echo        DB 없이도 서버는 띄울 수 있으나 점검 기능 사용 불가.
            pause
        ) else (
            echo       postgres-db 기동 완료 (docker-compose v1)
            timeout /t 3 /nobreak >nul
        )
    ) else (
        echo       postgres-db 기동 완료 (docker compose v2)
        timeout /t 3 /nobreak >nul
    )
) else (
    echo       postgres-db 실행 중
)

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
start "주통기 진단 서버" /MIN cmd /k "chcp 65001 >nul & set PYTHONIOENCODING=utf-8 & set PYTHONUTF8=1 & python main.py"

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
