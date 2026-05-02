from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from jutonggi_parser.db import JutonggiRepository
from jutonggi_parser.parser import JutonggiParser


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="주통기 PDF를 JSON/DB로 적재")
    p.add_argument("pdf", help="주통기 가이드 PDF 경로")
    p.add_argument("--json-out", default="parsed_items.json", help="정규화 JSON 저장 경로")
    p.add_argument(
        "--db-dsn",
        default="postgresql://admin:admin123@localhost:5432/jtk_db",
        help="PostgreSQL DSN (예: postgresql://user:pass@host:5432/dbname)",
    )
    return p


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = build_cli().parse_args()

    parser = JutonggiParser(args.pdf)
    items = parser.parse()

    json_path = Path(args.json_out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    repo = JutonggiRepository(args.db_dsn)
    repo.initialize()
    summary = repo.sync_items(items)

    print(f"items={len(items)}")
    print(f"json={json_path}")
    print(f"db_dsn={args.db_dsn}")
    print(f"added={summary['added']}")
    print(f"updated={summary['updated']}")
    print(f"deleted={summary['deleted']}")
    print(f"unchanged={summary['unchanged']}")
    print(f"history_upserted={summary['history_upserted']}")
    print(f"changelog_inserted={summary['changelog_inserted']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())