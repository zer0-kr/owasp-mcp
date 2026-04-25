from __future__ import annotations

import logging
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

_MAX_BYTES = 50 * 1024 * 1024
_ALLOWED_HOSTS = {"nvlpubs.nist.gov", "csrc.nist.gov", "doi.org", "dx.doi.org"}


async def download_file(url: str, dest: Path) -> Path:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(follow_redirects=True) as client:
        resp = await client.get(url, timeout=60)
        resp.raise_for_status()
        if len(resp.content) > _MAX_BYTES:
            raise ValueError(f"File too large: {len(resp.content)} bytes")
        dest.write_bytes(resp.content)
    return dest


def convert_pdf_to_markdown(path: Path, pages: str | None = None) -> str:
    import pymupdf4llm
    if pages:
        parts = pages.split("-")
        start = int(parts[0]) - 1
        end = int(parts[1]) if len(parts) > 1 else start + 1
        page_nums = list(range(start, end))
        return pymupdf4llm.to_markdown(str(path), pages=page_nums)
    return pymupdf4llm.to_markdown(str(path), pages=list(range(10)))


def get_pdf_toc(path: Path) -> str:
    import pymupdf
    doc = pymupdf.open(str(path))
    toc = doc.get_toc()
    doc.close()
    if not toc:
        return "No table of contents found."
    lines = ["## Table of Contents\n"]
    for level, title, page in toc:
        indent = "  " * (level - 1)
        lines.append(f"{indent}- {title} (p.{page})")
    return "\n".join(lines)
