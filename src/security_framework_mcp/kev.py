from __future__ import annotations

import json
import logging
import re
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
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("KEV cache read failed, will re-fetch: %s", exc)

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

    _DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')

    async def search_catalog(
        self,
        *,
        vendor: str | None = None,
        product: str | None = None,
        date_added_after: str | None = None,
        date_added_before: str | None = None,
        ransomware_only: bool = False,
        limit: int = 20,
    ) -> tuple[list[dict], int]:
        if date_added_after and not self._DATE_RE.match(date_added_after):
            raise ValueError(f"Invalid date format: {date_added_after}. Use YYYY-MM-DD")
        if date_added_before and not self._DATE_RE.match(date_added_before):
            raise ValueError(f"Invalid date format: {date_added_before}. Use YYYY-MM-DD")
        catalog = await self._ensure_catalog()
        results = catalog.get("vulnerabilities", [])

        if vendor:
            vendor_lower = vendor.lower()
            results = [v for v in results if vendor_lower in v.get("vendorProject", "").lower()]
        if product:
            product_lower = product.lower()
            results = [v for v in results if product_lower in v.get("product", "").lower()]
        if date_added_after:
            results = [v for v in results if v.get("dateAdded", "") >= date_added_after]
        if date_added_before:
            results = [v for v in results if v.get("dateAdded", "") <= date_added_before]
        if ransomware_only:
            results = [v for v in results if v.get("knownRansomwareCampaignUse", "").lower() == "known"]

        results.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        total = len(results)
        return results[:limit], total
