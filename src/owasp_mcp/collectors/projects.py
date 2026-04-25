from __future__ import annotations

import logging
import sqlite3

import httpx

log = logging.getLogger(__name__)

PROJECTS_URL = (
    "https://raw.githubusercontent.com/OWASP/owasp.github.io"
    "/main/_data/projects.json"
)

LEVEL_LABELS = {
    "4": "Flagship",
    "3.5": "Production",
    "3": "Lab",
    "2": "Incubator",
    "-1": "Retired",
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    name TEXT PRIMARY KEY,
    title TEXT,
    url TEXT,
    level TEXT,
    level_label TEXT,
    type TEXT,
    pitch TEXT,
    created TEXT,
    updated TEXT,
    codeurl TEXT,
    region TEXT,
    country TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS projects_fts USING fts5(
    name, title, pitch, type, level_label,
    content='projects', content_rowid='rowid'
);
"""


def scrape_projects(conn: sqlite3.Connection) -> int:
    resp = httpx.get(PROJECTS_URL, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    projects = resp.json()

    rows = []
    for p in projects:
        level_raw = str(p.get("level", "")).strip()
        level_label = LEVEL_LABELS.get(level_raw, "Unknown")
        rows.append((
            p.get("name", ""),
            p.get("title", ""),
            p.get("url", ""),
            level_raw,
            level_label,
            p.get("type", ""),
            p.get("pitch", ""),
            p.get("created", ""),
            p.get("updated", ""),
            p.get("codeurl", ""),
            p.get("region", ""),
            p.get("country", ""),
        ))

    conn.executemany(
        "INSERT OR REPLACE INTO projects "
        "(name, title, url, level, level_label, type, pitch, created, updated, codeurl, region, country) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d OWASP projects", len(rows))
    return len(rows)
