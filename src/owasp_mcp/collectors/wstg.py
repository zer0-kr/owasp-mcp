from __future__ import annotations

import logging
import sqlite3

import httpx

log = logging.getLogger(__name__)

WSTG_URL = (
    "https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.json"
)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS wstg (
    test_id TEXT PRIMARY KEY,
    category TEXT,
    category_id TEXT,
    name TEXT,
    reference TEXT,
    objectives TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS wstg_fts USING fts5(
    test_id, category, name, objectives,
    content='wstg', content_rowid='rowid'
);
"""


def scrape_wstg(conn: sqlite3.Connection) -> int:
    resp = httpx.get(WSTG_URL, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    data = resp.json()

    rows = []
    categories = data.get("categories", {})
    for cat_name, cat_data in categories.items():
        cat_id = cat_data.get("id", "")
        for test in cat_data.get("tests", []):
            objectives = "; ".join(test.get("objectives", []))
            rows.append((
                test.get("id", ""),
                cat_name,
                cat_id,
                test.get("name", ""),
                test.get("reference", ""),
                objectives,
            ))

    conn.executemany(
        "INSERT OR REPLACE INTO wstg "
        "(test_id, category, category_id, name, reference, objectives) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d WSTG tests", len(rows))
    return len(rows)
