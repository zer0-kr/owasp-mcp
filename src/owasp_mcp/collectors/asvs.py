from __future__ import annotations

import logging
import sqlite3

import httpx

log = logging.getLogger(__name__)

ASVS_URL = (
    "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/docs_en/"
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"
)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS asvs (
    req_id TEXT PRIMARY KEY,
    chapter_id TEXT,
    chapter_name TEXT,
    section_id TEXT,
    section_name TEXT,
    req_description TEXT,
    level TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS asvs_fts USING fts5(
    req_id, chapter_name, section_name, req_description,
    content='asvs', content_rowid='rowid'
);
"""


def scrape_asvs(conn: sqlite3.Connection) -> int:
    resp = httpx.get(ASVS_URL, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    data = resp.json()

    requirements = data.get("requirements", [])
    rows = []
    for r in requirements:
        rows.append((
            r.get("req_id", ""),
            r.get("chapter_id", ""),
            r.get("chapter_name", ""),
            r.get("section_id", ""),
            r.get("section_name", ""),
            r.get("req_description", ""),
            str(r.get("L", "")),
        ))

    conn.executemany(
        "INSERT OR REPLACE INTO asvs "
        "(req_id, chapter_id, chapter_name, section_id, section_name, req_description, level) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d ASVS requirements", len(rows))
    return len(rows)
