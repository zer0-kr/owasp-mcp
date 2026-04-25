from __future__ import annotations

import io
import logging
import sqlite3
from typing import Any

import httpx
import openpyxl

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_publications (
    id TEXT PRIMARY KEY,
    series TEXT,
    number TEXT,
    title TEXT,
    abstract TEXT,
    status TEXT,
    pub_date TEXT,
    keywords TEXT,
    topics TEXT,
    doi TEXT,
    url TEXT
);
CREATE INDEX IF NOT EXISTS idx_nist_pub_series ON nist_publications(series);
CREATE INDEX IF NOT EXISTS idx_nist_pub_status ON nist_publications(status);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_publications_fts USING fts5(
    id, series, title, abstract, keywords, topics,
    content='nist_publications', content_rowid='rowid'
);
"""

_XLSX_URL = "https://csrc.nist.gov/files/pubs/shared/docs/NIST-Cybersecurity-Publications.xlsx"

_SERIES_MAP = {
    "SP": "SP",
    "FIPS": "FIPS",
    "IR": "IR",
    "CSWP": "CSWP",
    "White Paper": "White Paper",
}


def scrape_nist_publications(conn: sqlite3.Connection) -> int:
    resp = httpx.get(_XLSX_URL, timeout=90, follow_redirects=True)
    resp.raise_for_status()

    wb = openpyxl.load_workbook(io.BytesIO(resp.content), read_only=True)
    ws = wb.active
    all_rows = list(ws.iter_rows(values_only=True))
    wb.close()

    if len(all_rows) < 2:
        log.warning("NIST publications XLSX is empty or has no data rows")
        return 0

    header = [str(h or "").strip() for h in all_rows[0]]
    header_map: dict[str, int] = {}
    for i, h in enumerate(header):
        h_lower = h.lower()
        if "pubid" in h_lower:
            header_map["pubid"] = i
        elif "series" in h_lower and "series" not in header_map:
            header_map["series"] = i
        elif h_lower == "publication number" or h_lower == "number":
            header_map["number"] = i
        elif "title" in h_lower and "title" not in header_map:
            header_map["title"] = i
        elif "abstract" in h_lower:
            header_map["abstract"] = i
        elif h_lower == "stage":
            header_map["status"] = i
        elif "release date" in h_lower or "citation date" in h_lower:
            if "pub_date" not in header_map:
                header_map["pub_date"] = i
        elif "keyword" in h_lower:
            header_map["keywords"] = i
        elif "topic" in h_lower:
            header_map["topics"] = i
        elif h_lower == "doi":
            header_map["doi"] = i
        elif h_lower == "currenturl" or h_lower == "url":
            header_map["url"] = i

    def _get(row: tuple, key: str) -> str:
        idx = header_map.get(key)
        if idx is None or idx >= len(row):
            return ""
        val = row[idx]
        return str(val).strip() if val else ""

    rows_to_insert = []
    for row in all_rows[1:]:
        pub_id = _get(row, "pubid").strip()
        if not pub_id:
            continue

        series = _get(row, "series")
        number = _get(row, "number")
        title = _get(row, "title")
        abstract = _get(row, "abstract")[:5000] if _get(row, "abstract") else ""
        status = _get(row, "status")
        pub_date = _get(row, "pub_date")
        keywords = _get(row, "keywords")[:2000] if _get(row, "keywords") else ""
        topics = _get(row, "topics")[:2000] if _get(row, "topics") else ""
        doi = _get(row, "doi")
        url = _get(row, "url")

        clean_id = pub_id.replace("NIST", "").replace("  ", " ").strip()

        rows_to_insert.append((
            clean_id, series, number, title, abstract,
            status, pub_date, keywords, topics, doi, url,
        ))

    conn.executemany(
        "INSERT OR REPLACE INTO nist_publications "
        "(id, series, number, title, abstract, status, pub_date, keywords, topics, doi, url) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows_to_insert,
    )
    conn.commit()
    log.info("Loaded %d NIST publications", len(rows_to_insert))
    return len(rows_to_insert)
