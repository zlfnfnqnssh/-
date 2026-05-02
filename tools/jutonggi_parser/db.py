from __future__ import annotations

import json
from typing import Iterable

import psycopg
from psycopg.rows import dict_row

LATEST_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    domain TEXT NOT NULL,
    domain_name TEXT NOT NULL,
    os_type TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    target TEXT NOT NULL,
    check_content TEXT NOT NULL,
    check_purpose TEXT NOT NULL,
    security_threat TEXT NOT NULL,
    criteria_good TEXT NOT NULL,
    criteria_bad TEXT NOT NULL,
    action TEXT NOT NULL,
    action_impact TEXT NOT NULL,
    note TEXT NOT NULL,
    page_start INTEGER NOT NULL,
    pdf_version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    raw_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
"""

HISTORY_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities_history (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL,
    prefix TEXT NOT NULL,
    domain TEXT NOT NULL,
    domain_name TEXT NOT NULL,
    os_type TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    target TEXT NOT NULL,
    check_content TEXT NOT NULL,
    check_purpose TEXT NOT NULL,
    security_threat TEXT NOT NULL,
    criteria_good TEXT NOT NULL,
    criteria_bad TEXT NOT NULL,
    action TEXT NOT NULL,
    action_impact TEXT NOT NULL,
    note TEXT NOT NULL,
    page_start INTEGER NOT NULL,
    pdf_version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    raw_json JSONB NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(code, pdf_version, content_hash)
);
"""

HISTORY_MIGRATION_SQL = [
    """
    ALTER TABLE vulnerabilities_history
    DROP CONSTRAINT IF EXISTS vulnerabilities_history_code_pdf_version_key;
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS ux_vh_code_version_hash
    ON vulnerabilities_history (code, pdf_version, content_hash);
    """,
]

CHANGELOG_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS item_changelog (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL,
    change_type TEXT NOT NULL,
    old_pdf_version TEXT,
    new_pdf_version TEXT,
    old_content_hash TEXT,
    new_content_hash TEXT,
    changed_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    old_snapshot JSONB,
    new_snapshot JSONB,
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
"""

UPSERT_LATEST_SQL = """
INSERT INTO vulnerabilities (
    code, prefix, domain, domain_name, os_type, category,
    severity, title, target, check_content, check_purpose,
    security_threat, criteria_good, criteria_bad, action,
    action_impact, note, page_start, pdf_version, content_hash, raw_json
)
VALUES (
    %(code)s, %(prefix)s, %(domain)s, %(domain_name)s, %(os_type)s, %(category)s,
    %(severity)s, %(title)s, %(target)s, %(check_content)s, %(check_purpose)s,
    %(security_threat)s, %(criteria_good)s, %(criteria_bad)s, %(action)s,
    %(action_impact)s, %(note)s, %(page_start)s, %(pdf_version)s, %(content_hash)s, %(raw_json)s::jsonb
)
ON CONFLICT(code) DO UPDATE SET
    prefix = EXCLUDED.prefix,
    domain = EXCLUDED.domain,
    domain_name = EXCLUDED.domain_name,
    os_type = EXCLUDED.os_type,
    category = EXCLUDED.category,
    severity = EXCLUDED.severity,
    title = EXCLUDED.title,
    target = EXCLUDED.target,
    check_content = EXCLUDED.check_content,
    check_purpose = EXCLUDED.check_purpose,
    security_threat = EXCLUDED.security_threat,
    criteria_good = EXCLUDED.criteria_good,
    criteria_bad = EXCLUDED.criteria_bad,
    action = EXCLUDED.action,
    action_impact = EXCLUDED.action_impact,
    note = EXCLUDED.note,
    page_start = EXCLUDED.page_start,
    pdf_version = EXCLUDED.pdf_version,
    content_hash = EXCLUDED.content_hash,
    raw_json = EXCLUDED.raw_json,
    updated_at = CURRENT_TIMESTAMP;
"""

UPSERT_HISTORY_SQL = """
INSERT INTO vulnerabilities_history (
    code, prefix, domain, domain_name, os_type, category,
    severity, title, target, check_content, check_purpose,
    security_threat, criteria_good, criteria_bad, action,
    action_impact, note, page_start, pdf_version, content_hash, raw_json
)
VALUES (
    %(code)s, %(prefix)s, %(domain)s, %(domain_name)s, %(os_type)s, %(category)s,
    %(severity)s, %(title)s, %(target)s, %(check_content)s, %(check_purpose)s,
    %(security_threat)s, %(criteria_good)s, %(criteria_bad)s, %(action)s,
    %(action_impact)s, %(note)s, %(page_start)s, %(pdf_version)s, %(content_hash)s, %(raw_json)s::jsonb
)
ON CONFLICT(code, pdf_version, content_hash) DO UPDATE SET
    prefix = EXCLUDED.prefix,
    domain = EXCLUDED.domain,
    domain_name = EXCLUDED.domain_name,
    os_type = EXCLUDED.os_type,
    category = EXCLUDED.category,
    severity = EXCLUDED.severity,
    title = EXCLUDED.title,
    target = EXCLUDED.target,
    check_content = EXCLUDED.check_content,
    check_purpose = EXCLUDED.check_purpose,
    security_threat = EXCLUDED.security_threat,
    criteria_good = EXCLUDED.criteria_good,
    criteria_bad = EXCLUDED.criteria_bad,
    action = EXCLUDED.action,
    action_impact = EXCLUDED.action_impact,
    note = EXCLUDED.note,
    page_start = EXCLUDED.page_start,
    raw_json = EXCLUDED.raw_json,
    ingested_at = CURRENT_TIMESTAMP;
"""

INSERT_CHANGELOG_SQL = """
INSERT INTO item_changelog (
    code, change_type, old_pdf_version, new_pdf_version,
    old_content_hash, new_content_hash, changed_fields, old_snapshot, new_snapshot
)
VALUES (
    %(code)s, %(change_type)s, %(old_pdf_version)s, %(new_pdf_version)s,
    %(old_content_hash)s, %(new_content_hash)s,
    %(changed_fields)s::jsonb, %(old_snapshot)s::jsonb, %(new_snapshot)s::jsonb
);
"""

FETCH_LATEST_SQL = """
SELECT code, prefix, domain, domain_name, os_type, category, severity, title,
       target, check_content, check_purpose, security_threat, criteria_good,
       criteria_bad, action, action_impact, note, page_start, pdf_version,
       content_hash, raw_json
FROM vulnerabilities;
"""

DIFF_FIELDS = [
    "prefix",
    "domain",
    "domain_name",
    "os_type",
    "category",
    "severity",
    "title",
    "target",
    "check_content",
    "check_purpose",
    "security_threat",
    "criteria_good",
    "criteria_bad",
    "action",
    "action_impact",
    "note",
    "page_start",
]


class JutonggiRepository:
    def __init__(self, dsn="postgresql://admin:admin123@localhost:5432/jtk_db"):
        self.dsn = dsn

    def initialize(self) -> None:
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(LATEST_SCHEMA_SQL)
                cur.execute(HISTORY_SCHEMA_SQL)
                cur.execute(CHANGELOG_SCHEMA_SQL)
                for sql in HISTORY_MIGRATION_SQL:
                    cur.execute(sql)
            conn.commit()

    def sync_items(self, items: Iterable[dict]) -> dict:
        payload = [self._to_row(item) for item in items]
        if not payload:
            return {
                "total_incoming": 0,
                "added": 0,
                "updated": 0,
                "deleted": 0,
                "unchanged": 0,
                "latest_upserted": 0,
                "history_upserted": 0,
                "changelog_inserted": 0,
            }

        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(FETCH_LATEST_SQL)
                prev_rows = cur.fetchall()

            prev_by_code = {row["code"]: row for row in prev_rows}
            new_by_code = {row["code"]: row for row in payload}

            added, updated, deleted, unchanged, changelog_rows = self._build_diff(prev_by_code, new_by_code)

            with conn.cursor() as cur:
                cur.executemany(UPSERT_LATEST_SQL, payload)

                if deleted:
                    cur.execute("DELETE FROM vulnerabilities WHERE code = ANY(%s)", (deleted,))

                cur.executemany(UPSERT_HISTORY_SQL, payload)

                if changelog_rows:
                    cur.executemany(INSERT_CHANGELOG_SQL, changelog_rows)

            conn.commit()

        return {
            "total_incoming": len(payload),
            "added": len(added),
            "updated": len(updated),
            "deleted": len(deleted),
            "unchanged": len(unchanged),
            "latest_upserted": len(payload),
            "history_upserted": len(payload),
            "changelog_inserted": len(changelog_rows),
        }

    def _to_row(self, item: dict) -> dict:
        row = dict(item)
        row.setdefault("note", "")
        row["raw_json"] = json.dumps(item, ensure_ascii=False)
        return row

    def _build_diff(self, prev_by_code: dict, new_by_code: dict) -> tuple[list[str], list[str], list[str], list[str], list[dict]]:
        prev_codes = set(prev_by_code)
        new_codes = set(new_by_code)

        added = sorted(new_codes - prev_codes)
        deleted = sorted(prev_codes - new_codes)
        common = sorted(new_codes & prev_codes)

        updated: list[str] = []
        unchanged: list[str] = []
        changelog_rows: list[dict] = []

        for code in added:
            new_row = new_by_code[code]
            changelog_rows.append(
                {
                    "code": code,
                    "change_type": "added",
                    "old_pdf_version": None,
                    "new_pdf_version": new_row.get("pdf_version"),
                    "old_content_hash": None,
                    "new_content_hash": new_row.get("content_hash"),
                    "changed_fields": json.dumps(DIFF_FIELDS, ensure_ascii=False),
                    "old_snapshot": None,
                    "new_snapshot": new_row["raw_json"],
                }
            )

        for code in deleted:
            old_row = prev_by_code[code]
            changelog_rows.append(
                {
                    "code": code,
                    "change_type": "deleted",
                    "old_pdf_version": old_row.get("pdf_version"),
                    "new_pdf_version": None,
                    "old_content_hash": old_row.get("content_hash"),
                    "new_content_hash": None,
                    "changed_fields": json.dumps([], ensure_ascii=False),
                    "old_snapshot": json.dumps(old_row.get("raw_json"), ensure_ascii=False),
                    "new_snapshot": None,
                }
            )

        for code in common:
            old_row = prev_by_code[code]
            new_row = new_by_code[code]
            changed_fields = [field for field in DIFF_FIELDS if old_row.get(field) != new_row.get(field)]
            if changed_fields:
                updated.append(code)
                changelog_rows.append(
                    {
                        "code": code,
                        "change_type": "updated",
                        "old_pdf_version": old_row.get("pdf_version"),
                        "new_pdf_version": new_row.get("pdf_version"),
                        "old_content_hash": old_row.get("content_hash"),
                        "new_content_hash": new_row.get("content_hash"),
                        "changed_fields": json.dumps(changed_fields, ensure_ascii=False),
                        "old_snapshot": json.dumps(old_row.get("raw_json"), ensure_ascii=False),
                        "new_snapshot": new_row["raw_json"],
                    }
                )
            else:
                unchanged.append(code)

        return added, updated, deleted, unchanged, changelog_rows