# ============================================================
#  주통기 취약점 자동 진단 시스템 - 원클릭 런처 (Windows / PowerShell)
# ============================================================
#  실행: start_server.bat 더블클릭 (내부에서 이 파일 호출)
#       또는 PowerShell 에서 직접: .\start_server.ps1
#  - Python 3.10+ 와 Docker 가 설치돼 있어야 함
#  - 처음 실행 시 의존성 자동 설치 (5~10분)
#  - UTF-8 한글 안전 (cp949 콘솔에서도 깨지지 않음)
# ============================================================

# UTF-8 콘솔 강제 — 가장 먼저 실행해야 한글 echo 안전
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8 = '1'

$ROOT = $PSScriptRoot
$APP  = Join-Path $ROOT 'vulnerability-scanner'
if (-not (Test-Path $APP)) {
    Write-Host "[ERROR] vulnerability-scanner 디렉토리를 찾을 수 없음." -ForegroundColor Red
    Pause; exit 1
}
Set-Location $APP

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " 주통기 취약점 진단 시스템 - 원클릭 런처 (PowerShell)"     -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Python 확인 ─────────────────────────────────────────
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "[ERROR] Python 이 설치되지 않음." -ForegroundColor Red
    Write-Host "        https://www.python.org/downloads/ 에서 3.10+ 설치 후 다시 실행."
    Pause; exit 1
}
$pyver = & python --version 2>&1
Write-Host "[1/5] Python: $pyver" -ForegroundColor Green

# ── 2. 의존성 설치 (마커로 한 번만) ─────────────────────────
$DEPS_MARKER = Join-Path $ROOT '.deps_installed'
if (-not (Test-Path $DEPS_MARKER)) {
    Write-Host "[2/5] 의존성 설치 중... (5~10분 소요, 처음 한 번만)" -ForegroundColor Yellow
    & python -m pip install --upgrade pip --quiet
    & python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] 의존성 설치 실패. requirements.txt 확인." -ForegroundColor Red
        Pause; exit 1
    }
    "" | Out-File -FilePath $DEPS_MARKER -Encoding utf8
    Write-Host "      의존성 설치 완료" -ForegroundColor Green
} else {
    Write-Host "[2/5] 의존성: 이미 설치됨 (.deps_installed 마커 존재)" -ForegroundColor DarkGray
}

# ── 3. Docker 확인 + postgres-db 자동 기동 ─────────────────
Write-Host "[3/5] Docker postgres-db 확인..."
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Host "      [WARN] docker 명령을 찾을 수 없음. Docker Desktop 설치 필요." -ForegroundColor Yellow
} else {
    $running = (docker ps --filter "name=postgres-db" --format "{{.Names}}" 2>$null) -match "postgres-db"
    if ($running) {
        Write-Host "      postgres-db 실행 중" -ForegroundColor Green
    } else {
        Write-Host "      postgres-db 가 실행 중이 아님. Docker Compose 로 기동 시도..."
        $compose_yml = Join-Path $ROOT 'docker-compose.yml'
        $started = $false

        # docker compose v2 (공백) 우선
        & docker compose -f $compose_yml up -d postgres-db 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      postgres-db 기동 완료 (docker compose v2)" -ForegroundColor Green
            $started = $true
        } else {
            # docker-compose v1 fallback
            & docker-compose -f $compose_yml up -d postgres-db 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "      postgres-db 기동 완료 (docker-compose v1)" -ForegroundColor Green
                $started = $true
            }
        }
        if (-not $started) {
            Write-Host "      [WARN] Docker 자동 기동 실패. 수동으로 docker compose up -d 실행 필요." -ForegroundColor Yellow
            Write-Host "             DB 없이도 서버는 띄울 수 있으나 점검 기능 사용 불가."
        } else {
            Start-Sleep -Seconds 3
        }
    }
}

# ── 4. .env 자동 생성 ──────────────────────────────────────
if (-not (Test-Path '.env')) {
    if (Test-Path '.env.example') {
        Copy-Item '.env.example' '.env'
        Write-Host "[4/5] .env 자동 생성 (.env.example -> .env)" -ForegroundColor Green
    } else {
        Write-Host "[4/5] [WARN] .env / .env.example 없음. PG 비밀번호가 기본값일 때만 동작." -ForegroundColor Yellow
    }
} else {
    Write-Host "[4/5] .env: 이미 존재" -ForegroundColor DarkGray
}

# ── 5. 서버 기동 (background, 새 PowerShell 창) ─────────────
$LOG_FILE = Join-Path $ROOT 'server.log'
$PID_FILE = Join-Path $ROOT '.server.pid'

# 8081 점유 중이면 스킵
$listenPid = $null
try {
    $conn = Get-NetTCPConnection -LocalPort 8081 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) { $listenPid = $conn.OwningProcess }
} catch {}

if ($listenPid) {
    Write-Host "[5/5] 8081 포트가 이미 사용 중 (PID=$listenPid). 기존 서버 그대로 사용." -ForegroundColor Yellow
} else {
    Write-Host "[5/5] 서버 기동 (포트 8081, 로그: $LOG_FILE)..."
    # 새 PowerShell 창에서 UTF-8 + python main.py 실행 (창 살아있게 -NoExit)
    $proc = Start-Process powershell -ArgumentList @(
        '-NoExit',
        '-Command',
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; `$env:PYTHONIOENCODING='utf-8'; `$env:PYTHONUTF8='1'; cd '$APP'; python main.py 2>&1 | Tee-Object '$LOG_FILE'"
    ) -WindowStyle Minimized -PassThru
    $proc.Id | Out-File -FilePath $PID_FILE -Encoding utf8
    Start-Sleep -Seconds 5
}

# ── 6. 동작 확인 + 브라우저 ───────────────────────────────
$URL = 'http://localhost:8081/login'
$ok = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri $URL -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($resp.StatusCode -eq 200 -or $resp.StatusCode -eq 303) {
            $ok = $true; break
        }
    } catch {
        # redirect (303) 도 catch 될 수 있음 — Status 만 확인
        if ($_.Exception.Response.StatusCode.value__ -in 200, 303) {
            $ok = $true; break
        }
    }
    Start-Sleep -Seconds 1
}
if ($ok) {
    Write-Host "      서버 응답 정상" -ForegroundColor Green
} else {
    Write-Host "      [WARN] 서버 응답 비정상" -ForegroundColor Yellow
    if (Test-Path $LOG_FILE) {
        Write-Host "      ── server.log 마지막 에러 라인 ─────────────────"
        Get-Content $LOG_FILE -Tail 200 |
            Select-String -Pattern 'ERROR|Error|Exception|Traceback|Refused|Connect call failed' |
            Select-Object -Last 3 |
            ForEach-Object { Write-Host ("      {0}" -f $_.Line) }
        Write-Host "      ── 전체 로그: Get-Content $LOG_FILE ─Tail 50 ──"
    }
}

# 브라우저 자동 오픈
if (-not $env:NO_BROWSER) {
    Start-Process $URL
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " 서버 실행 중 — $URL"                                          -ForegroundColor Green
Write-Host " 로그인: admin / admin1234"
Write-Host " 로그:    Get-Content $LOG_FILE -Tail 50 -Wait"
if (Test-Path $PID_FILE) {
    $serverPid = Get-Content $PID_FILE
    Write-Host " 종료:    Stop-Process -Id $serverPid"
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "이 창은 닫아도 서버는 계속 실행됩니다."
Pause
