from __future__ import annotations

import logging

import httpx

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"


class EPSSClient:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(follow_redirects=True, timeout=30)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        if not cve_ids:
            return {}
        if len(cve_ids) > 100:
            results: dict[str, dict] = {}
            for i in range(0, len(cve_ids), 100):
                chunk = cve_ids[i:i + 100]
                results.update(await self._get_batch(chunk))
            return results
        return await self._get_batch(cve_ids)

    async def _get_batch(self, cve_ids: list[str]) -> dict[str, dict]:
        client = await self._ensure_client()
        try:
            resp = await client.get(EPSS_URL, params={"cve": ",".join(cve_ids)})
            resp.raise_for_status()
            data = resp.json()
            return {
                item["cve"]: {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                    "date": item.get("date", ""),
                }
                for item in data.get("data", [])
            }
        except Exception as exc:
            log.warning("EPSS fetch failed: %s", exc)
            return {}
