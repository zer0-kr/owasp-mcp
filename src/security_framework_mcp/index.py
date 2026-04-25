from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_framework_mcp.config import Config

log = logging.getLogger(__name__)

_DB_FILENAME = "security_framework_mcp.db"
_META_FILENAME = "index_meta.json"


class IndexManager:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._db_path = config.data_dir / _DB_FILENAME
        self._meta_path = config.data_dir / _META_FILENAME
        self._update_task: asyncio.Task[None] | None = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    async def ensure_index(self) -> Path:
        if not self._db_path.exists():
            log.info("No local database found — building from OWASP sources.")
            await self._build()
            return self._db_path

        if self._is_stale():
            log.info("Database is stale — scheduling background rebuild.")
            self._schedule_background_rebuild()

        return self._db_path

    async def force_update(self) -> str:
        await self._build()
        meta = self._read_meta()
        return meta.get("built_at", "unknown")

    def status(self) -> dict[str, Any]:
        exists = self._db_path.exists()
        meta = self._read_meta()

        last_check_ts = meta.get("last_check")
        last_check_human = None
        if last_check_ts is not None:
            last_check_human = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(last_check_ts)
            )

        return {
            "exists": exists,
            "built_at": meta.get("built_at"),
            "last_check": last_check_human,
            "db_size_bytes": self._db_path.stat().st_size if exists else None,
            "path": str(self._db_path),
        }

    def _is_stale(self) -> bool:
        meta = self._read_meta()
        last_check = meta.get("last_check")
        if last_check is None:
            return True
        return (time.time() - last_check) > self._config.update_interval

    def _schedule_background_rebuild(self) -> None:
        if self._update_task is not None and not self._update_task.done():
            return
        self._update_task = asyncio.create_task(self._background_rebuild())

    async def _background_rebuild(self) -> None:
        try:
            await self._build()
        except Exception:
            log.warning("Background index rebuild failed.", exc_info=True)

    async def _build(self) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._build_sync)

    def _build_sync(self) -> None:
        from security_framework_mcp.collectors.projects import (
            CREATE_TABLE_SQL as PROJECTS_SQL,
            FTS_SQL as PROJECTS_FTS,
            scrape_projects,
        )
        from security_framework_mcp.collectors.asvs import (
            CREATE_TABLE_SQL as ASVS_SQL,
            FTS_SQL as ASVS_FTS,
            scrape_asvs,
        )
        from security_framework_mcp.collectors.wstg import (
            CREATE_TABLE_SQL as WSTG_SQL,
            FTS_SQL as WSTG_FTS,
            scrape_wstg,
        )
        from security_framework_mcp.collectors.top10 import (
            CREATE_TABLE_SQL as TOP10_SQL,
            FTS_SQL as TOP10_FTS,
            scrape_top10,
        )
        from security_framework_mcp.collectors.cheatsheets import (
            CREATE_TABLE_SQL as CHEATSHEETS_SQL,
            FTS_SQL as CHEATSHEETS_FTS,
            scrape_cheatsheets,
        )
        from security_framework_mcp.collectors.api_top10 import (
            CREATE_TABLE_SQL as API_TOP10_SQL,
            FTS_SQL as API_TOP10_FTS,
            scrape_api_top10,
        )
        from security_framework_mcp.collectors.llm_top10 import (
            CREATE_TABLE_SQL as LLM_TOP10_SQL,
            FTS_SQL as LLM_TOP10_FTS,
            scrape_llm_top10,
        )
        from security_framework_mcp.collectors.proactive_controls import (
            CREATE_TABLE_SQL as PROACTIVE_SQL,
            FTS_SQL as PROACTIVE_FTS,
            scrape_proactive_controls,
        )
        from security_framework_mcp.collectors.masvs import (
            CREATE_TABLE_SQL as MASVS_SQL,
            FTS_SQL as MASVS_FTS,
            scrape_masvs,
        )
        from security_framework_mcp.collectors.cwe_data import (
            CREATE_TABLE_SQL as CWE_SQL,
            FTS_SQL as CWE_FTS,
            scrape_cwes,
        )
        from security_framework_mcp.collectors.mcp_top10 import (
            CREATE_TABLE_SQL as MCP_TOP10_SQL,
            FTS_SQL as MCP_TOP10_FTS,
            scrape_mcp_top10,
        )
        from security_framework_mcp.collectors.nist_controls import (
            CREATE_TABLE_SQL as NIST_CTRL_SQL,
            FTS_SQL as NIST_CTRL_FTS,
            scrape_nist_controls,
        )
        from security_framework_mcp.collectors.nist_csf import (
            CREATE_TABLE_SQL as NIST_CSF_SQL,
            FTS_SQL as NIST_CSF_FTS,
            scrape_nist_csf,
        )
        from security_framework_mcp.collectors.nist_glossary import (
            CREATE_TABLE_SQL as NIST_GLOSS_SQL,
            FTS_SQL as NIST_GLOSS_FTS,
            scrape_nist_glossary,
        )
        from security_framework_mcp.collectors.nist_publications import (
            CREATE_TABLE_SQL as NIST_PUB_SQL,
            FTS_SQL as NIST_PUB_FTS,
            scrape_nist_publications,
        )
        from security_framework_mcp.collectors.nist_cmvp import (
            CREATE_TABLE_SQL as NIST_CMVP_SQL,
            FTS_SQL as NIST_CMVP_FTS,
            scrape_nist_cmvp,
        )
        from security_framework_mcp.collectors.nist_nice import (
            CREATE_TABLE_SQL as NIST_NICE_SQL,
            scrape_nist_nice,
        )

        output_dir = str(self._config.data_dir)
        os.makedirs(output_dir, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            suffix=".db", prefix=".security_framework_mcp_build_", dir=output_dir
        )
        os.close(fd)

        _META_SQL = "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"

        log.info("Building security framework database from sources ...")

        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

            for sql in [
                PROJECTS_SQL, ASVS_SQL, WSTG_SQL, TOP10_SQL, CHEATSHEETS_SQL,
                API_TOP10_SQL, LLM_TOP10_SQL, PROACTIVE_SQL, MASVS_SQL, CWE_SQL, MCP_TOP10_SQL,
                NIST_CTRL_SQL, NIST_CSF_SQL, NIST_GLOSS_SQL,
                NIST_PUB_SQL, NIST_CMVP_SQL, NIST_NICE_SQL, _META_SQL,
            ]:
                conn.executescript(sql)

            for fts_sql in [
                PROJECTS_FTS, ASVS_FTS, WSTG_FTS, TOP10_FTS, CHEATSHEETS_FTS,
                API_TOP10_FTS, LLM_TOP10_FTS, PROACTIVE_FTS, MASVS_FTS, CWE_FTS, MCP_TOP10_FTS,
                NIST_CTRL_FTS, NIST_CSF_FTS, NIST_GLOSS_FTS,
                NIST_PUB_FTS, NIST_CMVP_FTS,
            ]:
                conn.executescript(fts_sql)

            scrapers = [
                ("projects", scrape_projects),
                ("asvs", scrape_asvs),
                ("wstg", scrape_wstg),
                ("top10", scrape_top10),
                ("cheatsheets", scrape_cheatsheets),
                ("api_top10", scrape_api_top10),
                ("llm_top10", scrape_llm_top10),
                ("proactive_controls", scrape_proactive_controls),
                ("masvs", scrape_masvs),
                ("cwes", scrape_cwes),
                ("mcp_top10", scrape_mcp_top10),
                ("nist_controls", scrape_nist_controls),
                ("nist_csf", scrape_nist_csf),
                ("nist_glossary", scrape_nist_glossary),
                ("nist_publications", scrape_nist_publications),
                ("nist_cmvp", scrape_nist_cmvp),
                ("nist_nice", scrape_nist_nice),
            ]

            results: dict[str, int] = {}
            for name, scraper_fn in scrapers:
                log.info("  Building: %s ...", name)
                try:
                    results[name] = scraper_fn(conn)
                except Exception:
                    log.exception("  FAILED: %s", name)
                    results[name] = 0

            for fts in [
                "projects_fts", "asvs_fts", "wstg_fts", "top10_fts", "cheatsheets_fts",
                "api_top10_fts", "llm_top10_fts", "proactive_controls_fts", "masvs_fts", "cwes_fts", "mcp_top10_fts",
                "nist_controls_fts", "nist_csf_fts", "nist_glossary_fts",
                "nist_publications_fts", "nist_cmvp_fts", "nist_nice_fts",
            ]:
                try:
                    conn.execute(f"INSERT INTO {fts}({fts}) VALUES('rebuild')")
                except Exception:
                    log.exception("  FTS rebuild failed: %s", fts)

            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("built_at", now),
            )
            conn.commit()

            conn.execute("VACUUM")
            conn.execute("ANALYZE")
            conn.close()

            os.replace(tmp_path, str(self._db_path))
            self._write_meta(now, time.time())

            total = sum(results.values())
            log.info("Database built: %d total rows across %s", total, list(results.keys()))

        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def _read_meta(self) -> dict[str, Any]:
        if not self._meta_path.exists():
            return {}
        try:
            return json.loads(self._meta_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _write_meta(self, built_at: str, timestamp: float) -> None:
        payload = {"built_at": built_at, "last_check": timestamp}
        self._meta_path.write_text(json.dumps(payload))
