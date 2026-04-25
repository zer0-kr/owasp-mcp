from __future__ import annotations

import logging
import sys

from fastmcp import FastMCP

from owasp_mcp import __version__
from owasp_mcp.config import get_config
from owasp_mcp.index import IndexManager
from owasp_mcp.tools.owasp_tools import register_tools

mcp = FastMCP(
    name="owasp-mcp",
    instructions=(
        "OWASP MCP server providing unified access to all OWASP projects, "
        "standards, and security guidelines. Use search_owasp for cross-source "
        "search, list_projects/search_projects/get_project for the 418+ project "
        "catalog (Flagship/Production/Lab/Incubator), get_top10 for Top 10 2021, "
        "get_asvs for ASVS 5.0, get_wstg for Web Security Testing Guide, "
        "get_cheatsheet for Cheat Sheets, and cross_reference for CWE mappings."
    ),
)


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    config = get_config()
    index_mgr = IndexManager(config)

    register_tools(mcp, index_mgr)

    @mcp.resource("owasp://about")
    def about() -> str:
        info = index_mgr.status()
        return (
            "# OWASP MCP Server\n\n"
            f"- **Version:** {__version__}\n"
            f"- **Database available:** {'Yes' if info['exists'] else 'No'}\n"
            f"- **Database built:** {info.get('built_at', 'never')}\n"
            f"- **Database path:** `{info['path']}`\n\n"
            "## Tools\n\n"
            "- `list_projects` — Browse all 418+ OWASP projects\n"
            "- `search_projects` — Search projects by keyword\n"
            "- `get_project` — Get project details\n"
            "- `search_owasp` — Cross-source search (projects + ASVS + WSTG + Top 10 + Cheat Sheets)\n"
            "- `get_top10` — OWASP Top 10 2021 with CWE mappings\n"
            "- `get_asvs` — ASVS 5.0 requirements\n"
            "- `get_wstg` — WSTG test cases\n"
            "- `get_cheatsheet` — Cheat Sheets (100+)\n"
            "- `cross_reference` — CWE ↔ Top 10 ↔ ASVS mapping\n"
            "- `update_database` / `database_status` — Manage local index\n"
        )

    mcp.run(transport="stdio")
