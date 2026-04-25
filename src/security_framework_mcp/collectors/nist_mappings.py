from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_framework TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_framework TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relationship TEXT
);
CREATE INDEX IF NOT EXISTS idx_map_source ON nist_mappings(source_framework, source_id);
CREATE INDEX IF NOT EXISTS idx_map_target ON nist_mappings(target_framework, target_id);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_mappings_fts USING fts5(
    source_framework, source_id, target_framework, target_id,
    content='nist_mappings', content_rowid='rowid'
);
"""

# CSF 2.0 → SP 800-53 key mappings (from NIST CPRT)
_MAPPINGS: list[tuple[str, str, str, str, str]] = [
    ("CSF", "GV.OC", "SP800-53", "PM-7", "related"),
    ("CSF", "GV.OC", "SP800-53", "PM-9", "related"),
    ("CSF", "GV.OC", "SP800-53", "PM-11", "related"),
    ("CSF", "GV.RM", "SP800-53", "PM-9", "related"),
    ("CSF", "GV.RM", "SP800-53", "PM-28", "related"),
    ("CSF", "GV.RM", "SP800-53", "RA-1", "related"),
    ("CSF", "GV.RR", "SP800-53", "PM-1", "related"),
    ("CSF", "GV.RR", "SP800-53", "PM-2", "related"),
    ("CSF", "GV.SC", "SP800-53", "SR-1", "related"),
    ("CSF", "GV.SC", "SP800-53", "SR-2", "related"),
    ("CSF", "GV.SC", "SP800-53", "SR-3", "related"),
    ("CSF", "ID.AM", "SP800-53", "CM-8", "related"),
    ("CSF", "ID.AM", "SP800-53", "CM-12", "related"),
    ("CSF", "ID.AM", "SP800-53", "PM-5", "related"),
    ("CSF", "ID.RA", "SP800-53", "RA-3", "related"),
    ("CSF", "ID.RA", "SP800-53", "RA-5", "related"),
    ("CSF", "ID.RA", "SP800-53", "SI-5", "related"),
    ("CSF", "ID.IM", "SP800-53", "CA-2", "related"),
    ("CSF", "ID.IM", "SP800-53", "CA-7", "related"),
    ("CSF", "ID.IM", "SP800-53", "PM-14", "related"),
    ("CSF", "PR.AA", "SP800-53", "AC-1", "related"),
    ("CSF", "PR.AA", "SP800-53", "AC-2", "related"),
    ("CSF", "PR.AA", "SP800-53", "AC-3", "related"),
    ("CSF", "PR.AA", "SP800-53", "AC-6", "related"),
    ("CSF", "PR.AA", "SP800-53", "IA-1", "related"),
    ("CSF", "PR.AA", "SP800-53", "IA-2", "related"),
    ("CSF", "PR.AA", "SP800-53", "IA-5", "related"),
    ("CSF", "PR.AT", "SP800-53", "AT-1", "related"),
    ("CSF", "PR.AT", "SP800-53", "AT-2", "related"),
    ("CSF", "PR.AT", "SP800-53", "AT-3", "related"),
    ("CSF", "PR.DS", "SP800-53", "SC-7", "related"),
    ("CSF", "PR.DS", "SP800-53", "SC-8", "related"),
    ("CSF", "PR.DS", "SP800-53", "SC-28", "related"),
    ("CSF", "PR.DS", "SP800-53", "MP-2", "related"),
    ("CSF", "PR.PS", "SP800-53", "MA-2", "related"),
    ("CSF", "PR.PS", "SP800-53", "MA-4", "related"),
    ("CSF", "PR.PS", "SP800-53", "PE-1", "related"),
    ("CSF", "PR.IR", "SP800-53", "CP-2", "related"),
    ("CSF", "PR.IR", "SP800-53", "CP-10", "related"),
    ("CSF", "PR.IR", "SP800-53", "IR-4", "related"),
    ("CSF", "DE.CM", "SP800-53", "AU-6", "related"),
    ("CSF", "DE.CM", "SP800-53", "CA-7", "related"),
    ("CSF", "DE.CM", "SP800-53", "SI-4", "related"),
    ("CSF", "DE.AE", "SP800-53", "IR-4", "related"),
    ("CSF", "DE.AE", "SP800-53", "RA-5", "related"),
    ("CSF", "DE.AE", "SP800-53", "SI-4", "related"),
    ("CSF", "RS.MA", "SP800-53", "IR-1", "related"),
    ("CSF", "RS.MA", "SP800-53", "IR-4", "related"),
    ("CSF", "RS.MA", "SP800-53", "IR-5", "related"),
    ("CSF", "RS.AN", "SP800-53", "IR-4", "related"),
    ("CSF", "RS.AN", "SP800-53", "AU-6", "related"),
    ("CSF", "RS.CO", "SP800-53", "IR-6", "related"),
    ("CSF", "RS.CO", "SP800-53", "IR-7", "related"),
    ("CSF", "RS.MI", "SP800-53", "IR-4", "related"),
    ("CSF", "RC.RP", "SP800-53", "CP-10", "related"),
    ("CSF", "RC.RP", "SP800-53", "IR-4", "related"),
    ("CSF", "RC.CO", "SP800-53", "IR-7", "related"),
]


def scrape_nist_mappings(conn: sqlite3.Connection) -> int:
    conn.executemany(
        "INSERT OR REPLACE INTO nist_mappings (source_framework, source_id, target_framework, target_id, relationship) "
        "VALUES (?, ?, ?, ?, ?)",
        _MAPPINGS,
    )
    conn.commit()
    log.info("Loaded %d framework mappings", len(_MAPPINGS))
    return len(_MAPPINGS)
