-- db/schema.sql
-- DBWriter.init_schema() 가 자동 실행하므로 수동 실행은 선택사항

CREATE TABLE IF NOT EXISTS judge_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL,
    item_code     TEXT NOT NULL,
    item_name     TEXT,
    guideline_ref TEXT,
    result        TEXT,           -- 취약 / 양호 / 해당없음
    reason        TEXT,
    remediation   TEXT,
    confidence    REAL,
    judged_at     TEXT,
    UNIQUE(scan_id, item_code)
);

-- 웹 UI 버튼 단위: 항목별 패치 스크립트
CREATE TABLE IF NOT EXISTS patch_scripts (
    patch_id        TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    item_code       TEXT NOT NULL,
    item_name       TEXT,
    script_content  TEXT,
    description     TEXT,
    status          TEXT DEFAULT 'ready',  -- ready/running/success/failed/rewriting
    generated_at    TEXT
);

CREATE TABLE IF NOT EXISTS patch_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    patch_id        TEXT,
    scan_id         TEXT NOT NULL,
    item_code       TEXT NOT NULL,
    patch_script    TEXT,
    patch_stdout    TEXT,
    patch_stderr    TEXT,
    patch_exit_code INTEGER,
    verify_result   TEXT,          -- JSON
    attempt         INTEGER,
    patched_at      TEXT,
    patch_success   INTEGER        -- 0 or 1
);

CREATE TABLE IF NOT EXISTS final_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL,
    item_code       TEXT NOT NULL,
    item_name       TEXT,
    result          TEXT,          -- 취약/양호/해당없음/개선
    previous_result TEXT,
    status_change   TEXT,          -- 신규/유지/개선/악화/없음
    reason          TEXT,
    remediation     TEXT,
    confidence      REAL,
    patch_attempted INTEGER,
    patch_success   INTEGER,
    scan_date       TEXT,
    guideline_ref   TEXT,
    UNIQUE(scan_id, item_code)
);
