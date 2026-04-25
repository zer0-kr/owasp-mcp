from __future__ import annotations

import asyncio
import logging
import time

import httpx

log = logging.getLogger(__name__)


class NVDClient:
    BASE = "https://services.nvd.nist.gov/rest/json"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self._last_request = 0.0
        self._min_interval = 0.6 if api_key else 6.0
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(follow_redirects=True, timeout=30)
        return self._client

    async def _get(self, endpoint: str, params: dict) -> dict:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        client = await self._ensure_client()
        resp = await client.get(
            f"{self.BASE}/{endpoint}",
            params=params,
            headers=headers,
        )
        resp.raise_for_status()
        self._last_request = time.monotonic()
        return resp.json()

    async def search_cves(
        self,
        *,
        keyword: str | None = None,
        severity: str | None = None,
        cwe_id: str | None = None,
        results_per_page: int = 10,
        start_index: int = 0,
    ) -> dict:
        params: dict = {"resultsPerPage": results_per_page, "startIndex": start_index}
        if keyword:
            params["keywordSearch"] = keyword
        if severity:
            params["cvssV3Severity"] = severity.upper()
        if cwe_id:
            cwe_upper = cwe_id.strip().upper()
            if not cwe_upper.startswith("CWE-"):
                cwe_upper = f"CWE-{cwe_upper}"
            params["cweId"] = cwe_upper
        return await self._get("cves/2.0", params)

    async def get_cve(self, cve_id: str) -> dict:
        return await self._get("cves/2.0", {"cveId": cve_id.strip().upper()})
