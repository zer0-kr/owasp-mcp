from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL = 86400


class KEVClient:
    def __init__(self, cache_dir: Path) -> None:
        self._cache_path = cache_dir / "kev_catalog.json"
        self._catalog: dict | None = None
        self._last_load = 0.0

    async def _ensure_catalog(self) -> dict:
        now = time.time()
        if self._catalog and (now - self._last_load) < KEV_CACHE_TTL:
            return self._catalog

        if self._cache_path.exists() and (now - self._cache_path.stat().st_mtime) < KEV_CACHE_TTL:
            try:
                self._catalog = json.loads(self._cache_path.read_text())
                self._last_load = now
                return self._catalog
            except (json.JSONDecodeError, OSError):
                pass

        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                resp = await client.get(KEV_URL, timeout=30)
                resp.raise_for_status()
                self._catalog = resp.json()
                self._last_load = now
                self._cache_path.parent.mkdir(parents=True, exist_ok=True)
                self._cache_path.write_text(json.dumps(self._catalog))
                log.info("KEV catalog loaded: %d vulnerabilities", len(self._catalog.get("vulnerabilities", [])))
        except Exception as exc:
            log.warning("Failed to fetch KEV catalog: %s", exc)
            if self._catalog is None:
                self._catalog = {"vulnerabilities": []}

        return self._catalog

    async def get_kev_entry(self, cve_id: str) -> dict | None:
        catalog = await self._ensure_catalog()
        for vuln in catalog.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id.upper():
                return vuln
        return None

    async def is_in_kev(self, cve_id: str) -> bool:
        return await self.get_kev_entry(cve_id) is not None

    async def get_kev_count(self) -> int:
        catalog = await self._ensure_catalog()
        return len(catalog.get("vulnerabilities", []))
