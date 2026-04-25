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

from owasp_mcp.config import Config

log = logging.getLogger(__name__)

_DB_FILENAME = "owasp_mcp.db"
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
        from owasp_mcp.collectors.projects import (
            CREATE_TABLE_SQL as PROJECTS_SQL,
            FTS_SQL as PROJECTS_FTS,
            scrape_projects,
        )
        from owasp_mcp.collectors.asvs import (
            CREATE_TABLE_SQL as ASVS_SQL,
            FTS_SQL as ASVS_FTS,
            scrape_asvs,
        )
        from owasp_mcp.collectors.wstg import (
            CREATE_TABLE_SQL as WSTG_SQL,
            FTS_SQL as WSTG_FTS,
            scrape_wstg,
        )
        from owasp_mcp.collectors.top10 import (
            CREATE_TABLE_SQL as TOP10_SQL,
            FTS_SQL as TOP10_FTS,
            scrape_top10,
        )
        from owasp_mcp.collectors.cheatsheets import (
            CREATE_TABLE_SQL as CHEATSHEETS_SQL,
            FTS_SQL as CHEATSHEETS_FTS,
            scrape_cheatsheets,
        )

        output_dir = str(self._config.data_dir)
        os.makedirs(output_dir, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            suffix=".db", prefix=".owasp_mcp_build_", dir=output_dir
        )
        os.close(fd)

        _META_SQL = "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"

        log.info("Building OWASP database from sources ...")

        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

            for sql in [PROJECTS_SQL, ASVS_SQL, WSTG_SQL, TOP10_SQL, CHEATSHEETS_SQL, _META_SQL]:
                conn.executescript(sql)

            for fts_sql in [PROJECTS_FTS, ASVS_FTS, WSTG_FTS, TOP10_FTS, CHEATSHEETS_FTS]:
                conn.executescript(fts_sql)

            scrapers = [
                ("projects", scrape_projects),
                ("asvs", scrape_asvs),
                ("wstg", scrape_wstg),
                ("top10", scrape_top10),
                ("cheatsheets", scrape_cheatsheets),
            ]

            results: dict[str, int] = {}
            for name, scraper_fn in scrapers:
                log.info("  Building: %s ...", name)
                try:
                    results[name] = scraper_fn(conn)
                except Exception:
                    log.exception("  FAILED: %s", name)
                    results[name] = 0

            for fts in ["projects_fts", "asvs_fts", "wstg_fts", "top10_fts", "cheatsheets_fts"]:
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
