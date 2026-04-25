from __future__ import annotations

import logging
import sqlite3

import httpx

log = logging.getLogger(__name__)

CHEATSHEETS_API_URL = (
    "https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets"
)

CHEATSHEET_RAW_BASE = (
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets"
)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cheatsheets (
    name TEXT PRIMARY KEY,
    filename TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS cheatsheets_fts USING fts5(
    name,
    content='cheatsheets', content_rowid='rowid'
);
"""


def scrape_cheatsheets(conn: sqlite3.Connection) -> int:
    resp = httpx.get(
        CHEATSHEETS_API_URL,
        timeout=30,
        follow_redirects=True,
        headers={"Accept": "application/vnd.github.v3+json"},
    )
    resp.raise_for_status()
    files = resp.json()

    rows = []
    for f in files:
        fname = f.get("name", "")
        if not fname.endswith(".md"):
            continue
        sheet_name = fname.replace("_", " ").removesuffix(".md")
        raw_url = f"{CHEATSHEET_RAW_BASE}/{fname}"
        rows.append((sheet_name, fname, raw_url))

    conn.executemany(
        "INSERT OR REPLACE INTO cheatsheets (name, filename, url) VALUES (?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d cheat sheet entries", len(rows))
    return len(rows)


def fetch_cheatsheet_content(name_or_filename: str) -> str:
    if name_or_filename.endswith(".md"):
        filename = name_or_filename
    else:
        filename = name_or_filename.replace(" ", "_") + "_Cheat_Sheet.md"

    url = f"{CHEATSHEET_RAW_BASE}/{filename}"

    resp = httpx.get(url, timeout=30, follow_redirects=True)
    if resp.status_code == 404:
        filename_alt = name_or_filename.replace(" ", "_") + ".md"
        url_alt = f"{CHEATSHEET_RAW_BASE}/{filename_alt}"
        resp = httpx.get(url_alt, timeout=30, follow_redirects=True)

    resp.raise_for_status()
    return resp.text
