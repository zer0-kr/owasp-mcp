from __future__ import annotations

import logging
import sqlite3
import defusedxml.ElementTree as ET

import httpx

log = logging.getLogger(__name__)

CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
_NS = {"capec": "http://capec.mitre.org/capec-3"}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS capec (
    capec_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    severity TEXT,
    likelihood TEXT,
    prerequisites TEXT,
    mitigations TEXT,
    related_cwes TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS capec_fts USING fts5(
    capec_id, name, description, related_cwes,
    content='capec', content_rowid='rowid'
);
"""


def _iter_text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def scrape_capec(conn: sqlite3.Connection) -> int:
    try:
        resp = httpx.get(CAPEC_XML_URL, timeout=120, follow_redirects=True)
        resp.raise_for_status()
    except Exception:
        log.warning("Failed to download CAPEC XML", exc_info=True)
        return 0

    root = ET.fromstring(resp.content)
    rows: list[tuple[str, str, str, str, str, str, str, str, str]] = []

    for ap in root.findall(".//capec:Attack_Pattern", _NS):
        if ap.get("Status") == "Deprecated":
            continue

        ap_id = ap.get("ID", "")
        name = ap.get("Name", "")
        capec_id = f"CAPEC-{ap_id}"

        description = _iter_text(ap.find("capec:Description", _NS))
        severity = _iter_text(ap.find("capec:Typical_Severity", _NS))
        likelihood = _iter_text(ap.find("capec:Likelihood_Of_Attack", _NS))

        prereqs: list[str] = []
        for p in ap.findall("capec:Prerequisites/capec:Prerequisite", _NS):
            text = "".join(p.itertext()).strip()
            if text:
                prereqs.append(text)
        prerequisites = "\n".join(prereqs)

        mits: list[str] = []
        for m in ap.findall("capec:Mitigations/capec:Mitigation", _NS):
            desc_el = m.find("capec:Description", _NS)
            if desc_el is not None:
                text = "".join(desc_el.itertext()).strip()
            else:
                text = "".join(m.itertext()).strip()
            if text:
                mits.append(text)
        mitigations = "\n".join(mits)

        cwes: list[str] = []
        for rw in ap.findall("capec:Related_Weaknesses/capec:Related_Weakness", _NS):
            cwe_id = rw.get("CWE_ID", "")
            if cwe_id:
                cwes.append(f"CWE-{cwe_id}")
        related_cwes = ",".join(cwes)

        url = f"https://capec.mitre.org/data/definitions/{ap_id}.html"

        rows.append((capec_id, name, description, severity, likelihood, prerequisites, mitigations, related_cwes, url))

    conn.executemany(
        "INSERT OR REPLACE INTO capec (capec_id, name, description, severity, likelihood, prerequisites, mitigations, related_cwes, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d CAPEC attack patterns", len(rows))
    return len(rows)
