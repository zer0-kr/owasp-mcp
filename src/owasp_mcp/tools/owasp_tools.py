from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from owasp_mcp import db
from owasp_mcp.collectors.cheatsheets import fetch_cheatsheet_content
from owasp_mcp.collectors.top10 import TOP10_2021
from owasp_mcp.collectors.api_top10 import API_TOP10_2023
from owasp_mcp.collectors.llm_top10 import LLM_TOP10_2025
from owasp_mcp.collectors.proactive_controls import PROACTIVE_CONTROLS_2024

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from owasp_mcp.index import IndexManager
    from owasp_mcp.nvd import NVDClient

log = logging.getLogger(__name__)

ProjectLevel = Literal["flagship", "production", "lab", "incubator", "retired", "all"]
ProjectType = Literal["documentation", "code", "tool", "all"]

_LEVEL_FILTER_MAP: dict[str, str] = {
    "flagship": "4",
    "production": "3.5",
    "lab": "3",
    "incubator": "2",
    "retired": "-1",
}

_SOURCE_TABLES: dict[str, str] = {
    "projects": "projects",
    "asvs": "asvs",
    "wstg": "wstg",
    "top10": "top10",
    "cheatsheets": "cheatsheets",
    "api_top10": "api_top10",
    "llm_top10": "llm_top10",
    "proactive_controls": "proactive_controls",
    "masvs": "masvs",
    "mcp_top10": "mcp_top10",
    "cwes": "cwes",
}

_SOURCE_LABELS: dict[str, str] = {
    "projects": "Projects",
    "asvs": "ASVS 5.0",
    "wstg": "WSTG",
    "top10": "Top 10 2021",
    "cheatsheets": "Cheat Sheets",
    "api_top10": "API Security Top 10 2023",
    "llm_top10": "LLM Top 10 2025",
    "proactive_controls": "Proactive Controls 2024",
    "masvs": "MASVS",
    "mcp_top10": "MCP Top 10 2025",
    "cwes": "CWE Database",
}


def _fmt_project(row: dict[str, Any]) -> str:
    level = row.get("level_label", "Unknown")
    return f"**{row.get('title', row.get('name', '?'))}** [{level}] — {row.get('pitch', '')}"


def _fmt_asvs(row: dict[str, Any]) -> str:
    return f"**{row.get('req_id', '?')}** (L{row.get('level', '?')}) [{row.get('section_name', '')}] — {row.get('req_description', '')[:200]}"


def _fmt_wstg(row: dict[str, Any]) -> str:
    return f"**{row.get('test_id', '?')}** [{row.get('category', '')}] — {row.get('name', '')}"


def _fmt_top10(row: dict[str, Any]) -> str:
    return f"**{row.get('id', '?')}** {row.get('name', '')} — {row.get('description', '')[:150]}"


def _fmt_cheatsheet(row: dict[str, Any]) -> str:
    return f"**{row.get('name', '?')}**"


def _fmt_api_top10(row: dict[str, Any]) -> str:
    return f"**{row.get('id', '?')}** {row.get('name', '')} — {row.get('description', '')[:150]}"


def _fmt_llm_top10(row: dict[str, Any]) -> str:
    return f"**{row.get('id', '?')}** {row.get('name', '')} — {row.get('description', '')[:150]}"


def _fmt_proactive(row: dict[str, Any]) -> str:
    return f"**{row.get('id', '?')}** {row.get('name', '')} — {row.get('description', '')[:150]}"


def _fmt_masvs(row: dict[str, Any]) -> str:
    return f"**{row.get('control_id', '?')}** [{row.get('category_name', '')}] — {row.get('statement', '')}"


def _fmt_mcp_top10(row: dict[str, Any]) -> str:
    return f"**{row.get('id', '?')}** {row.get('name', '')} — {row.get('description', '')[:150]}"


def _fmt_cwe(row: dict[str, Any]) -> str:
    return f"**{row.get('cwe_id', '?')}** {row.get('name', '')[:120]}"


_FORMATTERS = {
    "projects": _fmt_project,
    "asvs": _fmt_asvs,
    "wstg": _fmt_wstg,
    "top10": _fmt_top10,
    "cheatsheets": _fmt_cheatsheet,
    "api_top10": _fmt_api_top10,
    "llm_top10": _fmt_llm_top10,
    "proactive_controls": _fmt_proactive,
    "masvs": _fmt_masvs,
    "mcp_top10": _fmt_mcp_top10,
    "cwes": _fmt_cwe,
}


def register_tools(mcp: "FastMCP", index_mgr: "IndexManager", nvd_client: "NVDClient | None" = None) -> None:

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    async def update_database() -> str:
        """Rebuild the local OWASP database from upstream sources."""
        built_at = await index_mgr.force_update()
        return f"Database rebuilt at: {built_at}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def database_status() -> str:
        """Show local database availability, freshness, and path."""
        info = index_mgr.status()
        return "\n".join([
            "## OWASP Database Status",
            f"- **Available:** {'Yes' if info['exists'] else 'No'}",
            f"- **Built:** {info.get('built_at', 'never')}",
            f"- **Last check:** {info.get('last_check', 'never')}",
            f"- **Size:** {info.get('db_size_bytes') or 0} bytes",
            f"- **Path:** `{info['path']}`",
        ])

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def list_projects(
        level: Annotated[
            ProjectLevel,
            Field(description="Filter by project level: flagship, production, lab, incubator, retired, or all"),
        ] = "all",
        type: Annotated[
            ProjectType,
            Field(description="Filter by type: documentation, code, tool, or all"),
        ] = "all",
        limit: Annotated[int, Field(ge=1, le=200, description="Max results")] = 50,
        offset: Annotated[int, Field(ge=0, description="Pagination offset")] = 0,
    ) -> str:
        """List OWASP projects. Includes Flagship, Production, Lab, and Incubator levels."""
        db_path = await index_mgr.ensure_index()

        filters: dict[str, Any] = {}
        if level != "all":
            filters["level"] = _LEVEL_FILTER_MAP[level]
        if type != "all":
            filters["type"] = type

        results, total = db.get_all(db_path, "projects", filters=filters, limit=limit, offset=offset)

        if not results:
            return "No projects found matching your filters."

        lines = [f"## OWASP Projects ({total} total)\n"]
        for row in results:
            lines.append(f"- {_fmt_project(row)}")

        if total > offset + limit:
            lines.append(f"\n_Use offset={offset + limit} for more results._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_projects(
        query: Annotated[str, Field(description="Search keywords", max_length=500)],
        limit: Annotated[int, Field(ge=1, le=50, description="Max results")] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Full-text search across all OWASP projects (name, title, pitch)."""
        db_path = await index_mgr.ensure_index()

        try:
            results, total = db.search_fts(db_path, "projects", query, limit=limit, offset=offset)
        except Exception as exc:
            raise ToolError(f"Search failed: {exc}") from exc

        if not results:
            return f"No projects found for '{query}'."

        lines = [f"## Project Search: {query} ({total} results)\n"]
        for row in results:
            lines.append(f"- {_fmt_project(row)}")

        if total > offset + limit:
            lines.append(f"\n_Use offset={offset + limit} for more._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_project(
        name: Annotated[str, Field(description="Project name (from projects list or search)", max_length=200)],
    ) -> str:
        """Get detailed info for a specific OWASP project."""
        db_path = await index_mgr.ensure_index()

        record = db.get_by_id(db_path, "projects", "name", name)
        if record is None:
            conn = db.get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT * FROM projects WHERE lower(name) = lower(?) OR lower(title) LIKE lower(?)",
                    (name, f"%{name}%"),
                ).fetchone()
                record = dict(row) if row else None
            finally:
                conn.close()

        if record is None:
            return f"Project '{name}' not found. Use list_projects or search_projects to find the correct name."

        level_label = record.get("level_label", "Unknown")
        lines = [
            f"# {record.get('title', record.get('name', '?'))}",
            "",
            f"- **Level:** {level_label}",
            f"- **Type:** {record.get('type', '?')}",
            f"- **URL:** {record.get('url', '')}",
        ]
        if record.get("codeurl"):
            lines.append(f"- **Code:** {record['codeurl']}")
        if record.get("pitch"):
            lines.append(f"- **Description:** {record['pitch']}")
        lines.append(f"- **Created:** {record.get('created', '?')}")
        lines.append(f"- **Last Updated:** {record.get('updated', '?')}")
        if record.get("region") and record["region"] != "Unknown":
            lines.append(f"- **Region:** {record['region']}")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_owasp(
        query: Annotated[str, Field(description="Search keywords", max_length=500)],
        limit: Annotated[int, Field(ge=1, le=50, description="Max results per source")] = 10,
    ) -> str:
        """Search across ALL OWASP data sources: projects, ASVS, WSTG, Top 10, and Cheat Sheets."""
        db_path = await index_mgr.ensure_index()

        sections: list[str] = []
        shown = 0

        for source, table in _SOURCE_TABLES.items():
            try:
                rows, total = db.search_fts(db_path, table, query, limit=min(5, limit))
            except Exception as exc:
                log.debug("Search failed for %s: %s", source, exc)
                continue

            if not rows:
                continue

            shown += len(rows)
            fmt = _FORMATTERS[source]
            lines = [f"### {_SOURCE_LABELS[source]} ({total} total)"]
            lines.extend(f"- {fmt(row)}" for row in rows)
            if total > len(rows):
                lines.append(f"_Use the specific tool for more {source} results._")
            sections.append("\n".join(lines))

        if not sections:
            return f"No OWASP results found for '{query}'."

        return f"## OWASP Search: {query}\n\n_Showing {shown} results_\n\n" + "\n\n".join(sections)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_top10(
        id: Annotated[
            str | None,
            Field(description="Top 10 item ID, e.g. 'A01:2021'. Omit to list all."),
        ] = None,
    ) -> str:
        """Get OWASP Top 10 2021 items with CWE mappings."""
        if id is None:
            lines = ["## OWASP Top 10 — 2021\n"]
            for item in TOP10_2021:
                lines.append(f"- **{item['id']}** — {item['name']}")
            return "\n".join(lines)

        id_upper = id.strip().upper()
        item = next((i for i in TOP10_2021 if i["id"] == id_upper), None)
        if item is None:
            return f"Top 10 item '{id}' not found. Valid IDs: A01:2021 through A10:2021."

        return "\n".join([
            f"# {item['id']} — {item['name']}",
            "",
            f"**URL:** {item['url']}",
            "",
            "## Description",
            item["description"],
            "",
            "## Associated CWEs",
            item["cwes"],
        ])

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_asvs(
        chapter: Annotated[
            str | None,
            Field(description="Filter by chapter ID, e.g. 'V1'. Omit for all."),
        ] = None,
        level: Annotated[
            str | None,
            Field(description="Filter by ASVS level: '1', '2', or '3'. Omit for all."),
        ] = None,
        query: Annotated[
            str | None,
            Field(description="Search keywords within ASVS requirements", max_length=500),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 30,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Get OWASP ASVS 5.0 verification requirements. Filter by chapter, level, or search."""
        db_path = await index_mgr.ensure_index()

        if query:
            filters: dict[str, Any] = {}
            if chapter:
                filters["chapter_id"] = chapter.upper()
            if level:
                filters["level"] = level

            try:
                results, total = db.search_fts(
                    db_path, "asvs", query, filters=filters, limit=limit, offset=offset
                )
            except Exception as exc:
                raise ToolError(f"ASVS search failed: {exc}") from exc
        else:
            filters = {}
            if chapter:
                filters["chapter_id"] = chapter.upper()
            if level:
                filters["level"] = level
            results, total = db.get_all(db_path, "asvs", filters=filters, limit=limit, offset=offset)

        if not results:
            return "No ASVS requirements found matching your criteria."

        lines = [f"## ASVS 5.0 Requirements ({total} total)\n"]
        for row in results:
            lines.append(f"- {_fmt_asvs(row)}")

        if total > offset + limit:
            lines.append(f"\n_Use offset={offset + limit} for more._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_wstg(
        category: Annotated[
            str | None,
            Field(description="Filter by category ID, e.g. 'WSTG-INFO'. Omit for all."),
        ] = None,
        query: Annotated[
            str | None,
            Field(description="Search keywords within WSTG tests", max_length=500),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 30,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Get OWASP Web Security Testing Guide (WSTG) test cases."""
        db_path = await index_mgr.ensure_index()

        if query:
            filters: dict[str, Any] = {}
            if category:
                filters["category_id"] = category.upper()

            try:
                results, total = db.search_fts(
                    db_path, "wstg", query, filters=filters, limit=limit, offset=offset
                )
            except Exception as exc:
                raise ToolError(f"WSTG search failed: {exc}") from exc
        else:
            filters = {}
            if category:
                filters["category_id"] = category.upper()
            results, total = db.get_all(db_path, "wstg", filters=filters, limit=limit, offset=offset)

        if not results:
            return "No WSTG tests found matching your criteria."

        lines = [f"## WSTG Tests ({total} total)\n"]
        for row in results:
            lines.append(f"- {_fmt_wstg(row)}")
            if row.get("objectives"):
                lines.append(f"  _Objectives: {row['objectives'][:200]}_")

        if total > offset + limit:
            lines.append(f"\n_Use offset={offset + limit} for more._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_cheatsheet(
        name: Annotated[
            str | None,
            Field(description="Cheat sheet name, e.g. 'SQL Injection Prevention'. Omit to list all available."),
        ] = None,
    ) -> str:
        """Get an OWASP Cheat Sheet by name, or list all available cheat sheets."""
        db_path = await index_mgr.ensure_index()

        if name is None:
            results, total = db.get_all(db_path, "cheatsheets", limit=200)
            if not results:
                return "No cheat sheets found. Try running update_database first."

            lines = [f"## OWASP Cheat Sheets ({total} available)\n"]
            for row in results:
                lines.append(f"- {row.get('name', '?')}")
            return "\n".join(lines)

        record = db.get_by_id(db_path, "cheatsheets", "name", name)
        if record is None:
            conn = db.get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT * FROM cheatsheets WHERE lower(name) LIKE lower(?)",
                    (f"%{name}%",),
                ).fetchone()
                record = dict(row) if row else None
            finally:
                conn.close()

        if record is None:
            return f"Cheat sheet '{name}' not found. Use get_cheatsheet() without arguments to list all."

        try:
            content = fetch_cheatsheet_content(record.get("filename", ""))
        except Exception as exc:
            raise ToolError(f"Failed to fetch cheat sheet content: {exc}") from exc

        return content

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def cross_reference(
        cwe: Annotated[
            str | None,
            Field(description="CWE ID to cross-reference, e.g. 'CWE-79'"),
        ] = None,
        top10_id: Annotated[
            str | None,
            Field(description="Top 10 ID to find related CWEs/ASVS, e.g. 'A03:2021'"),
        ] = None,
    ) -> str:
        """Cross-reference CWE IDs with OWASP Top 10, ASVS, and WSTG entries."""
        if not cwe and not top10_id:
            raise ToolError("Provide at least one of: cwe, top10_id")

        db_path = await index_mgr.ensure_index()
        sections: list[str] = []

        if cwe:
            cwe_upper = cwe.strip().upper()
            if not cwe_upper.startswith("CWE-"):
                cwe_upper = f"CWE-{cwe_upper}"

            cwe_num = cwe_upper.replace("CWE-", "")

            cwe_set_match = lambda cwes_str: cwe_upper in {c.strip() for c in cwes_str.split(",")}
            matched_top10 = [
                item for item in TOP10_2021
                if cwe_set_match(item["cwes"])
            ]
            if matched_top10:
                lines = ["### Top 10 Mapping"]
                for item in matched_top10:
                    lines.append(f"- **{item['id']}** — {item['name']}")
                sections.append("\n".join(lines))

            try:
                asvs_results, _ = db.search_fts(db_path, "asvs", cwe_num, limit=10)
                if asvs_results:
                    lines = ["### Related ASVS Requirements"]
                    for row in asvs_results:
                        lines.append(f"- {_fmt_asvs(row)}")
                    sections.append("\n".join(lines))
            except Exception:
                pass

            try:
                wstg_results, _ = db.search_fts(db_path, "wstg", cwe_num, limit=10)
                if not wstg_results:
                    terms = []
                    if "79" in cwe_num:
                        terms.append("XSS")
                    elif "89" in cwe_num:
                        terms.append("SQL Injection")
                    elif "918" in cwe_num:
                        terms.append("SSRF")
                    elif "352" in cwe_num:
                        terms.append("CSRF")
                    for term in terms:
                        wstg_results, _ = db.search_fts(db_path, "wstg", term, limit=10)
                        if wstg_results:
                            break

                if wstg_results:
                    lines = ["### Related WSTG Tests"]
                    for row in wstg_results:
                        lines.append(f"- {_fmt_wstg(row)}")
                    sections.append("\n".join(lines))
            except Exception:
                pass

        if top10_id:
            id_upper = top10_id.strip().upper()
            item = next((i for i in TOP10_2021 if i["id"] == id_upper), None)
            if item is None:
                return f"Top 10 item '{top10_id}' not found."

            sections.insert(0, f"## {item['id']} — {item['name']}\n\n{item['description']}")

            cwes = [c.strip() for c in item["cwes"].split(",")]
            sections.append(f"### Associated CWEs ({len(cwes)} total)\n{', '.join(cwes[:30])}")
            if len(cwes) > 30:
                sections[-1] += f"\n_...and {len(cwes) - 30} more_"

        header = f"## Cross-Reference: {cwe or top10_id}"
        if not sections:
            return f"{header}\n\nNo cross-references found."

        return f"{header}\n\n" + "\n\n".join(sections)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_api_top10(
        id: Annotated[
            str | None,
            Field(description="API Security Top 10 item ID, e.g. 'API1:2023'. Omit to list all."),
        ] = None,
    ) -> str:
        """Get OWASP API Security Top 10 2023 items with CWE mappings."""
        if id is None:
            lines = ["## OWASP API Security Top 10 — 2023\n"]
            for item in API_TOP10_2023:
                lines.append(f"- **{item['id']}** — {item['name']}")
            return "\n".join(lines)

        id_upper = id.strip().upper()
        item = next((i for i in API_TOP10_2023 if i["id"] == id_upper), None)
        if item is None:
            return f"API Top 10 item '{id}' not found. Valid IDs: API1:2023 through API10:2023."

        return "\n".join([
            f"# {item['id']} — {item['name']}",
            "",
            f"**URL:** {item['url']}",
            "",
            "## Description",
            item["description"],
            "",
            "## Associated CWEs",
            item["cwes"],
        ])

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_llm_top10(
        id: Annotated[
            str | None,
            Field(description="LLM Top 10 item ID, e.g. 'LLM01:2025'. Omit to list all."),
        ] = None,
    ) -> str:
        """Get OWASP Top 10 for LLM Applications 2025 items with CWE mappings."""
        if id is None:
            lines = ["## OWASP Top 10 for LLM Applications — 2025\n"]
            for item in LLM_TOP10_2025:
                lines.append(f"- **{item['id']}** — {item['name']}")
            return "\n".join(lines)

        id_upper = id.strip().upper()
        item = next((i for i in LLM_TOP10_2025 if i["id"] == id_upper), None)
        if item is None:
            return f"LLM Top 10 item '{id}' not found. Valid IDs: LLM01:2025 through LLM10:2025."

        return "\n".join([
            f"# {item['id']} — {item['name']}",
            "",
            f"**URL:** {item['url']}",
            "",
            "## Description",
            item["description"],
            "",
            "## Associated CWEs",
            item["cwes"],
        ])

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_proactive_controls(
        id: Annotated[
            str | None,
            Field(description="Control ID, e.g. 'C1'. Omit to list all."),
        ] = None,
    ) -> str:
        """Get OWASP Proactive Controls 2024 — defensive measures developers should implement."""
        if id is None:
            lines = ["## OWASP Proactive Controls — 2024\n"]
            for item in PROACTIVE_CONTROLS_2024:
                lines.append(f"- **{item['id']}** — {item['name']}")
            return "\n".join(lines)

        id_upper = id.strip().upper()
        item = next((i for i in PROACTIVE_CONTROLS_2024 if i["id"] == id_upper), None)
        if item is None:
            return f"Proactive Control '{id}' not found. Valid IDs: C1 through C10."

        return "\n".join([
            f"# {item['id']} — {item['name']}",
            "",
            "## Description",
            item["description"],
            "",
            "## Related Top 10 / CWEs",
            item["related_top10"],
        ])

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_masvs(
        category: Annotated[
            str | None,
            Field(description="Category ID, e.g. 'MASVS-STORAGE'. Omit for all."),
        ] = None,
        query: Annotated[
            str | None,
            Field(description="Search keywords within MASVS controls", max_length=500),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 30,
    ) -> str:
        """Get OWASP MASVS (Mobile Application Security Verification Standard) controls."""
        db_path = await index_mgr.ensure_index()

        if query:
            filters: dict[str, Any] = {}
            if category:
                filters["category_id"] = category.upper()
            try:
                results, total = db.search_fts(
                    db_path, "masvs", query, filters=filters, limit=limit
                )
            except Exception as exc:
                raise ToolError(f"MASVS search failed: {exc}") from exc
        else:
            filters = {}
            if category:
                filters["category_id"] = category.upper()
            results, total = db.get_all(db_path, "masvs", filters=filters, limit=limit)

        if not results:
            return "No MASVS controls found matching your criteria."

        lines = [f"## MASVS Controls ({total} total)\n"]
        for row in results:
            lines.append(f"- {_fmt_masvs(row)}")
            if row.get("description"):
                lines.append(f"  _{row['description'][:200]}_")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def assess_stack(
        stack: Annotated[str, Field(description="Technology stack description, e.g. 'React, Node.js, PostgreSQL, REST API'", max_length=1000)],
    ) -> str:
        """Given a technology stack, recommend relevant OWASP security guidelines, cheat sheets, and test cases."""
        db_path = await index_mgr.ensure_index()

        _STACK_KEYWORDS: dict[str, list[str]] = {
            "api": ["API", "REST", "GraphQL", "gRPC", "endpoint", "microservice"],
            "web": ["React", "Angular", "Vue", "Next", "frontend", "HTML", "JavaScript", "TypeScript", "browser", "web", "SPA"],
            "mobile": ["iOS", "Android", "React Native", "Flutter", "Swift", "Kotlin", "mobile"],
            "database": ["SQL", "PostgreSQL", "MySQL", "MongoDB", "Redis", "database", "NoSQL", "SQLite"],
            "auth": ["auth", "OAuth", "JWT", "SAML", "SSO", "login", "session", "token", "OIDC"],
            "cloud": ["AWS", "Azure", "GCP", "Docker", "Kubernetes", "Lambda", "serverless", "cloud"],
            "llm": ["LLM", "AI", "GPT", "Claude", "ML", "machine learning", "RAG", "embedding", "agent"],
            "crypto": ["encryption", "TLS", "SSL", "certificate", "crypto", "hash"],
        }

        stack_lower = stack.lower()
        matched_domains: set[str] = set()
        for domain, keywords in _STACK_KEYWORDS.items():
            if any(kw.lower() in stack_lower for kw in keywords):
                matched_domains.add(domain)

        if not matched_domains:
            matched_domains = {"web"}

        sections: list[str] = []

        if "api" in matched_domains:
            sections.append("### API Security\n- Review: **OWASP API Security Top 10 2023** (`get_api_top10`)\n- Key risks: Broken Object Level Authorization, Broken Authentication, Unrestricted Resource Consumption")

        if "web" in matched_domains:
            sections.append("### Web Security\n- Review: **OWASP Top 10 2021** (`get_top10`)\n- Test with: **WSTG** (`get_wstg`) — especially WSTG-INPV (Input Validation) and WSTG-CLNT (Client-side)\n- Apply: **Proactive Control C8** — Leverage Browser Security Features")

        if "mobile" in matched_domains:
            sections.append("### Mobile Security\n- Verify: **OWASP MASVS** (`get_masvs`) — all 8 categories\n- Key areas: MASVS-STORAGE, MASVS-CRYPTO, MASVS-NETWORK, MASVS-AUTH")

        if "llm" in matched_domains:
            sections.append("### AI/LLM Security\n- Review: **OWASP LLM Top 10 2025** (`get_llm_top10`)\n- Key risks: Prompt Injection, Sensitive Information Disclosure, Excessive Agency\n- Apply: Proactive Controls for input validation and output handling")

        if "database" in matched_domains:
            sections.append("### Database Security\n- Review: **ASVS V1** — Encoding and Sanitization (`get_asvs chapter=V1`)\n- Cheat Sheets: SQL Injection Prevention, Query Parameterization (`get_cheatsheet`)\n- Test: **WSTG-INPV-05** — SQL Injection testing")

        if "auth" in matched_domains:
            sections.append("### Authentication & Authorization\n- Verify: **ASVS V7** — Session Management, **ASVS V3** — Identity Verification\n- Apply: **Proactive Control C1** (Access Control), **C7** (Secure Digital Identities)\n- Cheat Sheets: Authentication, Session Management, Password Storage")

        if "cloud" in matched_domains:
            sections.append("### Cloud & Infrastructure\n- Apply: **Proactive Control C5** — Secure By Default Configurations\n- Cheat Sheets: Docker Security, Kubernetes Security\n- Test: **WSTG-CONF** — Configuration and Deployment Management")

        if "crypto" in matched_domains:
            sections.append("### Cryptography\n- Apply: **Proactive Control C2** — Use Cryptography to Protect Data\n- Verify: **ASVS V6** — Stored Cryptography\n- Cheat Sheets: Cryptographic Storage, Transport Layer Security")

        try:
            search_terms = [t.strip() for t in stack.split(",")][:3]
            for term in search_terms:
                term = term.strip()
                if len(term) < 2:
                    continue
                cs_results, _ = db.search_fts(db_path, "cheatsheets", term, limit=3)
                if cs_results:
                    names = [r.get("name", "") for r in cs_results]
                    sections.append(f"### Related Cheat Sheets for \"{term}\"\n" + "\n".join(f"- {n}" for n in names))
        except Exception:
            pass

        header = f"## Security Assessment: {stack}\n"
        if not sections:
            return f"{header}\nNo specific recommendations found. Use `search_owasp` to explore."

        return header + "\n\n".join(sections)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def generate_checklist(
        project_type: Annotated[
            Literal["web", "api", "mobile", "llm", "full"],
            Field(description="Project type: web, api, mobile, llm, or full (all combined)"),
        ],
        level: Annotated[
            Literal["basic", "standard", "comprehensive"],
            Field(description="Checklist depth: basic (~20 items), standard (~40), comprehensive (~60+)"),
        ] = "standard",
    ) -> str:
        """Generate a security testing checklist based on project type and depth level."""
        db_path = await index_mgr.ensure_index()

        limit_map = {"basic": 8, "standard": 15, "comprehensive": 30}
        per_section = limit_map[level]

        sections: list[str] = []
        item_count = 0

        if project_type in ("web", "full"):
            items = []
            for t10 in TOP10_2021[:per_section]:
                items.append(f"- [ ] **{t10['id']}** {t10['name']}")
                item_count += 1
            sections.append("### Web Application — Top 10 2021\n" + "\n".join(items))

            wstg_cats = ["WSTG-INFO", "WSTG-CONF", "WSTG-IDNT", "WSTG-ATHN", "WSTG-ATHZ", "WSTG-SESS", "WSTG-INPV", "WSTG-CLNT"]
            wstg_items = []
            for cat in wstg_cats[:per_section]:
                results, _ = db.get_all(db_path, "wstg", filters={"category_id": cat}, limit=3)
                for r in results:
                    wstg_items.append(f"- [ ] **{r['test_id']}** {r['name']}")
                    item_count += 1
            if wstg_items:
                sections.append("### Web — Testing (WSTG)\n" + "\n".join(wstg_items[:per_section]))

        if project_type in ("api", "full"):
            items = []
            for a in API_TOP10_2023[:per_section]:
                items.append(f"- [ ] **{a['id']}** {a['name']}")
                item_count += 1
            sections.append("### API Security — Top 10 2023\n" + "\n".join(items))

        if project_type in ("mobile", "full"):
            from owasp_mcp.collectors.masvs import MASVS_DATA
            items = []
            for cat_id, cat_name, controls in MASVS_DATA:
                for ctrl_id, statement, _ in controls[:2 if level == "basic" else 99]:
                    items.append(f"- [ ] **{ctrl_id}** {statement}")
                    item_count += 1
            sections.append("### Mobile Security — MASVS\n" + "\n".join(items[:per_section]))

        if project_type in ("llm", "full"):
            items = []
            for l in LLM_TOP10_2025[:per_section]:
                items.append(f"- [ ] **{l['id']}** {l['name']}")
                item_count += 1
            sections.append("### AI/LLM Security — Top 10 2025\n" + "\n".join(items))

        asvs_items = []
        asvs_level = "1" if level == "basic" else "2" if level == "standard" else "3"
        results, _ = db.get_all(db_path, "asvs", filters={"level": asvs_level}, limit=per_section)
        for r in results:
            asvs_items.append(f"- [ ] **{r['req_id']}** {r['req_description'][:120]}")
            item_count += 1
        if asvs_items:
            sections.append(f"### Verification — ASVS Level {asvs_level}\n" + "\n".join(asvs_items))

        pc_items = []
        for pc in PROACTIVE_CONTROLS_2024[:per_section]:
            pc_items.append(f"- [ ] **{pc['id']}** {pc['name']}")
            item_count += 1
        sections.append("### Defensive Controls — Proactive Controls 2024\n" + "\n".join(pc_items))

        header = f"## Security Checklist: {project_type.upper()} ({level})\n\n_{item_count} items_\n"
        return header + "\n\n".join(sections)

    from owasp_mcp.collectors.mcp_top10 import MCP_TOP10_2025

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True))
    async def search_cve(
        keyword: Annotated[str | None, Field(description="Search keyword, e.g. 'log4j'", max_length=500)] = None,
        cwe_id: Annotated[str | None, Field(description="Filter by CWE ID, e.g. 'CWE-79'")] = None,
        severity: Annotated[
            Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None,
            Field(description="Filter by CVSS v3 severity"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=20)] = 5,
    ) -> str:
        """Search the live NVD database for CVE vulnerabilities. Requires internet access."""
        if not keyword and not cwe_id and not severity:
            raise ToolError("Provide at least one of: keyword, cwe_id, or severity")

        if nvd_client is None:
            raise ToolError("NVD client not configured")

        try:
            data = await nvd_client.search_cves(
                keyword=keyword, cwe_id=cwe_id, severity=severity, results_per_page=limit,
            )
        except Exception as exc:
            raise ToolError(f"NVD API error: {exc}") from exc

        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", len(vulns))

        if not vulns:
            return f"No CVEs found for the given criteria."

        lines = [f"## NVD Search Results ({total} total, showing {len(vulns)})\n"]
        for v in vulns:
            cve = v.get("cve", v)
            cve_id_str = cve.get("id", "?")
            desc = next(
                (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            if len(desc) > 200:
                desc = desc[:197] + "..."

            score = "?"
            for bucket in ("cvssMetricV31", "cvssMetricV30"):
                metrics = cve.get("metrics", {}).get(bucket, [])
                if metrics:
                    cvss = metrics[0].get("cvssData", {})
                    score = f"{cvss.get('baseScore', '?')} {cvss.get('baseSeverity', '')}"
                    break

            lines.append(f"- **{cve_id_str}** (CVSS: {score}) — {desc}")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True))
    async def get_cve_detail(
        cve_id: Annotated[str, Field(description="CVE ID, e.g. 'CVE-2024-1234'", pattern=r"^[Cc][Vv][Ee]-\d{4}-\d{4,}$")],
    ) -> str:
        """Fetch detailed information for a specific CVE from the live NVD database."""
        if nvd_client is None:
            raise ToolError("NVD client not configured")

        try:
            data = await nvd_client.get_cve(cve_id)
        except Exception as exc:
            raise ToolError(f"NVD API error: {exc}") from exc

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"CVE '{cve_id}' not found."

        cve = vulns[0].get("cve", vulns[0])
        cve_id_str = cve.get("id", cve_id)

        lines = [f"# {cve_id_str}"]

        meta = []
        for key, label in [("published", "Published"), ("lastModified", "Modified"), ("vulnStatus", "Status")]:
            if cve.get(key):
                meta.append(f"{label}: {str(cve[key])[:10]}")
        if meta:
            lines.append(" | ".join(meta))
        lines.append("")

        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                lines.extend(["## Description", desc.get("value", ""), ""])
                break

        for bucket in ("cvssMetricV31", "cvssMetricV30"):
            metrics = cve.get("metrics", {}).get(bucket, [])
            if metrics:
                cvss = metrics[0].get("cvssData", {})
                lines.append(f"**CVSS:** {cvss.get('baseScore', '?')} {cvss.get('baseSeverity', '')} ({cvss.get('vectorString', '')})")
                break

        weaknesses = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en" and d.get("value"):
                    weaknesses.append(d["value"])
        if weaknesses:
            lines.append(f"**Weaknesses:** {', '.join(sorted(set(weaknesses)))}")

        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
        if refs:
            lines.append("\n## References")
            lines.extend(f"- {url}" for url in refs[:10])

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_mcp_top10(
        id: Annotated[
            str | None,
            Field(description="MCP Top 10 item ID, e.g. 'MCP01:2025'. Omit to list all."),
        ] = None,
    ) -> str:
        """Get OWASP Top 10 for MCP Servers 2025 — security risks specific to MCP deployments."""
        if id is None:
            lines = ["## OWASP Top 10 for MCP Servers — 2025\n"]
            for item in MCP_TOP10_2025:
                lines.append(f"- **{item['id']}** — {item['name']}")
            return "\n".join(lines)

        id_upper = id.strip().upper()
        item = next((i for i in MCP_TOP10_2025 if i["id"] == id_upper), None)
        if item is None:
            return f"MCP Top 10 item '{id}' not found. Valid IDs: MCP01:2025 through MCP10:2025."

        return "\n".join([
            f"# {item['id']} — {item['name']}",
            "",
            "## Description",
            item["description"],
            "",
            "## Impact",
            item["impact"],
            "",
            f"**Reference:** {MCP_TOP10_2025[0]['id']} series — https://owasp.org/www-project-mcp-top-10/",
        ])

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def assess_mcp_security(
        description: Annotated[str, Field(description="Describe your MCP server setup: what tools it exposes, how auth works, what data it accesses, how it's deployed", max_length=2000)],
    ) -> str:
        """Assess an MCP server deployment against the OWASP MCP Top 10 security risks."""
        desc_lower = description.lower()

        checks: list[tuple[str, str, str, bool]] = [
            ("MCP01", "Token Mismanagement", "Tokens/secrets in config, env vars, or context", any(kw in desc_lower for kw in ["token", "secret", "key", "credential", "password", "env"])),
            ("MCP02", "Scope Creep", "Over-privileged agents with broad permissions", any(kw in desc_lower for kw in ["admin", "all permission", "broad access", "full access", "root"])),
            ("MCP03", "Tool Poisoning", "Untrusted third-party tools or plugins", any(kw in desc_lower for kw in ["plugin", "third-party", "marketplace", "community", "external tool"])),
            ("MCP04", "Supply Chain", "Unverified dependencies or SDKs", any(kw in desc_lower for kw in ["npm", "pip", "dependency", "package", "library", "sdk"])),
            ("MCP05", "Command Injection", "Tools that execute system commands", any(kw in desc_lower for kw in ["shell", "exec", "command", "subprocess", "os.", "system("])),
            ("MCP06", "Intent Flow Subversion", "RAG or context from untrusted sources", any(kw in desc_lower for kw in ["rag", "retrieval", "context", "document", "embedding", "vector"])),
            ("MCP07", "Insufficient Auth", "Missing or weak authentication", any(kw in desc_lower for kw in ["no auth", "open", "public", "unauthenticated", "anyone"]) or not any(kw in desc_lower for kw in ["auth", "token", "oauth", "api key"])),
            ("MCP08", "Lack of Audit", "No logging or monitoring", not any(kw in desc_lower for kw in ["log", "audit", "monitor", "trace", "telemetry"])),
            ("MCP09", "Shadow Servers", "Unofficial or unmanaged deployments", any(kw in desc_lower for kw in ["test", "experiment", "dev server", "local", "prototype", "poc"])),
            ("MCP10", "Context Over-Sharing", "Shared context across users/sessions", any(kw in desc_lower for kw in ["shared", "multi-user", "multi-tenant", "session", "persistent context"])),
        ]

        risk_items: list[str] = []
        safe_items: list[str] = []

        for mcp_id, name, indicator, flagged in checks:
            item = next(i for i in MCP_TOP10_2025 if i["id"].startswith(mcp_id))
            if flagged:
                risk_items.append(f"- **{item['id']} {name}** — {indicator}\n  _{item['description'][:150]}_")
            else:
                safe_items.append(f"- **{item['id']} {name}** — No indicators detected")

        lines = [f"## MCP Security Assessment\n"]
        lines.append(f"_Assessed against OWASP MCP Top 10 (2025)_\n")

        if risk_items:
            lines.append(f"### Potential Risks ({len(risk_items)} found)\n")
            lines.extend(risk_items)
        else:
            lines.append("### No risks detected from description alone\n")

        if safe_items:
            lines.append(f"\n### No Indicators ({len(safe_items)} items)\n")
            lines.extend(safe_items)

        lines.append(f"\n### Recommendations")
        lines.append("1. Use `get_mcp_top10` for detailed guidance on each identified risk")
        lines.append("2. Implement authentication (MCP07) and audit logging (MCP08) as baseline controls")
        lines.append("3. Pin and verify all tool/plugin dependencies (MCP03, MCP04)")
        lines.append("4. Scope agent permissions to minimum required (MCP02)")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def threat_model(
        system: Annotated[str, Field(description="System description: components, data flows, trust boundaries, and technologies", max_length=3000)],
        methodology: Annotated[
            Literal["stride", "summary"],
            Field(description="STRIDE for detailed per-category analysis, summary for quick overview"),
        ] = "stride",
    ) -> str:
        """Generate a STRIDE-based threat model for a system using OWASP data for mitigations."""
        sys_lower = system.lower()

        _STRIDE = [
            ("Spoofing", "Pretending to be something or someone else",
             ["auth", "login", "identity", "credential", "session", "token", "certificate"],
             ["A07:2021 (Auth Failures)", "ASVS V3 (Session Mgmt)", "Proactive Control C7 (Secure Digital Identities)"],
             "get_asvs chapter=V3, get_proactive_controls id=C7, get_cheatsheet name=Authentication"),

            ("Tampering", "Modifying data or code without authorization",
             ["database", "file", "api", "input", "form", "upload", "storage", "write"],
             ["A03:2021 (Injection)", "A08:2021 (Integrity Failures)", "ASVS V1 (Encoding)", "Proactive Control C3 (Validate Input)"],
             "get_asvs chapter=V1, get_proactive_controls id=C3, get_cheatsheet name=Input Validation"),

            ("Repudiation", "Denying having performed an action",
             ["transaction", "payment", "audit", "log", "action", "event", "order"],
             ["A09:2021 (Logging Failures)", "Proactive Control C9 (Security Logging)", "WSTG-BUSL (Business Logic)"],
             "get_proactive_controls id=C9, get_wstg category=WSTG-BUSL"),

            ("Information Disclosure", "Exposing data to unauthorized parties",
             ["sensitive", "pii", "password", "secret", "key", "personal", "health", "financial", "api key"],
             ["A02:2021 (Crypto Failures)", "A01:2021 (Access Control)", "ASVS V6 (Stored Crypto)", "Proactive Control C2 (Cryptography)"],
             "get_asvs chapter=V6, get_proactive_controls id=C2, get_cheatsheet name=Cryptographic Storage"),

            ("Denial of Service", "Making a system unavailable",
             ["api", "public", "endpoint", "rate", "upload", "search", "query", "resource"],
             ["API4:2023 (Unrestricted Resource Consumption)", "ASVS V2 (Anti-automation)", "Proactive Control C5 (Secure Defaults)"],
             "get_api_top10 id=API4:2023, get_asvs chapter=V2"),

            ("Elevation of Privilege", "Gaining unauthorized access or capabilities",
             ["role", "admin", "permission", "privilege", "access control", "authorization", "rbac"],
             ["A01:2021 (Access Control)", "API5:2023 (Broken Function Level Auth)", "ASVS V4 (Access Control)", "Proactive Control C1 (Access Control)"],
             "get_asvs chapter=V4, get_proactive_controls id=C1, get_cheatsheet name=Access Control"),
        ]

        sections: list[str] = []

        for category, desc, keywords, references, tools_hint in _STRIDE:
            relevance = sum(1 for kw in keywords if kw in sys_lower)
            if methodology == "summary" and relevance == 0:
                continue

            risk = "High" if relevance >= 3 else "Medium" if relevance >= 1 else "Low"
            lines = [f"### {category} — {desc}"]
            lines.append(f"**Risk Level:** {risk} ({relevance} indicators matched)")
            lines.append(f"**OWASP References:** {', '.join(references)}")
            lines.append(f"**Recommended Tools:** `{tools_hint}`")
            sections.append("\n".join(lines))

        has_llm = any(kw in sys_lower for kw in ["llm", "ai", "gpt", "claude", "model", "agent", "rag"])
        has_mcp = any(kw in sys_lower for kw in ["mcp", "model context protocol", "tool server"])
        has_mobile = any(kw in sys_lower for kw in ["mobile", "ios", "android", "react native", "flutter", "swift", "kotlin"])

        if has_llm:
            sections.append("### AI/LLM-Specific Threats\n**Risk Level:** High\n"
                          "**Key Risks:** Prompt Injection (LLM01), Sensitive Info Disclosure (LLM02), Excessive Agency (LLM06)\n"
                          "**Recommended:** `get_llm_top10`")
        if has_mcp:
            sections.append("### MCP-Specific Threats\n**Risk Level:** High\n"
                          "**Key Risks:** Tool Poisoning (MCP03), Insufficient Auth (MCP07), Context Injection (MCP10)\n"
                          "**Recommended:** `get_mcp_top10`, `assess_mcp_security`")
        if has_mobile:
            sections.append("### Mobile-Specific Threats\n**Risk Level:** Medium\n"
                          "**Key Areas:** MASVS-STORAGE, MASVS-CRYPTO, MASVS-NETWORK, MASVS-AUTH\n"
                          "**Recommended:** `get_masvs`")

        header = f"## STRIDE Threat Model\n\n_System: {system[:100]}{'...' if len(system) > 100 else ''}_\n"
        if not sections:
            return f"{header}\nNo significant threats identified from the description. Provide more detail about components, data flows, and trust boundaries."

        return header + "\n\n".join(sections)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_cwe(
        id: Annotated[str, Field(description="CWE ID, e.g. 'CWE-79' or '79'", max_length=20)],
    ) -> str:
        """Look up a CWE (Common Weakness Enumeration) by ID with description and OWASP cross-references."""
        db_path = await index_mgr.ensure_index()

        cwe_id = id.strip().upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        record = db.get_by_id(db_path, "cwes", "cwe_id", cwe_id)
        if record is None:
            return f"CWE '{id}' not found in local database. Try https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"

        lines = [
            f"# {record['cwe_id']} — {record['name']}",
            "",
            "## Description",
            record["description"],
            "",
            f"**MITRE URL:** {record['url']}",
        ]

        cwe_set_match = lambda cwes_str: cwe_id in {c.strip() for c in cwes_str.split(",")}
        matched_top10 = [i for i in TOP10_2021 if cwe_set_match(i["cwes"])]
        matched_api = [i for i in API_TOP10_2023 if cwe_set_match(i["cwes"])]
        matched_llm = [i for i in LLM_TOP10_2025 if cwe_set_match(i["cwes"])]

        if matched_top10 or matched_api or matched_llm:
            lines.append("\n## OWASP Mappings")
            for item in matched_top10:
                lines.append(f"- **Top 10:** {item['id']} — {item['name']}")
            for item in matched_api:
                lines.append(f"- **API Top 10:** {item['id']} — {item['name']}")
            for item in matched_llm:
                lines.append(f"- **LLM Top 10:** {item['id']} — {item['name']}")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def compliance_map(
        framework: Annotated[
            Literal["pci-dss", "iso27001", "nist-800-53", "all"],
            Field(description="Compliance framework to map ASVS requirements to"),
        ] = "all",
        asvs_chapter: Annotated[
            str | None,
            Field(description="Filter by ASVS chapter, e.g. 'V1'"),
        ] = None,
    ) -> str:
        """Map OWASP ASVS requirements to compliance frameworks (PCI-DSS, ISO 27001, NIST 800-53)."""
        _COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
            "V1": {
                "pci-dss": ["6.5.1 (Injection flaws)"],
                "iso27001": ["A.14.2.5 (Secure system engineering principles)"],
                "nist-800-53": ["SI-10 (Information Input Validation)", "SI-15 (Information Output Filtering)"],
            },
            "V2": {
                "pci-dss": ["6.5.8 (Improper access control)"],
                "iso27001": ["A.14.2.5 (Secure system engineering principles)"],
                "nist-800-53": ["SI-10 (Information Input Validation)"],
            },
            "V3": {
                "pci-dss": ["6.5.10 (Broken authentication)"],
                "iso27001": ["A.9.4.2 (Secure log-on procedures)", "A.9.2.4 (Management of secret authentication)"],
                "nist-800-53": ["IA-2 (Identification and Authentication)", "IA-5 (Authenticator Management)"],
            },
            "V4": {
                "pci-dss": ["6.5.8 (Improper access control)", "7.1 (Limit access)"],
                "iso27001": ["A.9.1.1 (Access control policy)", "A.9.4.1 (Information access restriction)"],
                "nist-800-53": ["AC-3 (Access Enforcement)", "AC-6 (Least Privilege)"],
            },
            "V5": {
                "pci-dss": ["6.5.1 (Injection flaws)", "6.5.7 (XSS)"],
                "iso27001": ["A.14.2.5 (Secure system engineering principles)"],
                "nist-800-53": ["SI-10 (Information Input Validation)"],
            },
            "V6": {
                "pci-dss": ["3.4 (Render PAN unreadable)", "4.1 (Strong cryptography)"],
                "iso27001": ["A.10.1.1 (Policy on use of cryptographic controls)", "A.10.1.2 (Key management)"],
                "nist-800-53": ["SC-12 (Cryptographic Key Establishment)", "SC-13 (Cryptographic Protection)"],
            },
            "V7": {
                "pci-dss": ["6.5.10 (Broken authentication)", "8.1 (Identify users)"],
                "iso27001": ["A.9.4.2 (Secure log-on procedures)"],
                "nist-800-53": ["SC-23 (Session Authenticity)", "AC-12 (Session Termination)"],
            },
            "V8": {
                "pci-dss": ["6.5.4 (Insecure direct object references)"],
                "iso27001": ["A.14.1.2 (Securing application services)"],
                "nist-800-53": ["SC-8 (Transmission Confidentiality and Integrity)"],
            },
            "V9": {
                "pci-dss": ["4.1 (Strong cryptography for transmission)"],
                "iso27001": ["A.13.1.1 (Network controls)", "A.14.1.2 (Securing application services)"],
                "nist-800-53": ["SC-8 (Transmission Confidentiality)", "SC-23 (Session Authenticity)"],
            },
            "V10": {
                "pci-dss": ["6.3.2 (Review custom code)", "6.5 (Address common vulnerabilities)"],
                "iso27001": ["A.14.2.1 (Secure development policy)"],
                "nist-800-53": ["SA-11 (Developer Testing and Evaluation)", "SI-2 (Flaw Remediation)"],
            },
            "V11": {
                "pci-dss": ["6.5 (Address common coding vulnerabilities)"],
                "iso27001": ["A.14.2.5 (Secure system engineering principles)"],
                "nist-800-53": ["SA-11 (Developer Testing and Evaluation)"],
            },
            "V12": {
                "pci-dss": ["6.5.8 (Improper access control)"],
                "iso27001": ["A.13.1.3 (Segregation in networks)"],
                "nist-800-53": ["SC-4 (Information in Shared System Resources)"],
            },
            "V13": {
                "pci-dss": ["6.5.1 (Injection)", "6.5.4 (Insecure direct object references)"],
                "iso27001": ["A.14.1.2 (Securing application services on public networks)"],
                "nist-800-53": ["SI-10 (Information Input Validation)", "AC-3 (Access Enforcement)"],
            },
            "V14": {
                "pci-dss": ["2.2 (Configuration standards)", "6.2 (Security patches)"],
                "iso27001": ["A.12.6.1 (Management of technical vulnerabilities)", "A.14.2.2 (System change control)"],
                "nist-800-53": ["CM-6 (Configuration Settings)", "CM-7 (Least Functionality)"],
            },
        }

        frameworks = [framework] if framework != "all" else ["pci-dss", "iso27001", "nist-800-53"]
        chapters = [asvs_chapter.upper()] if asvs_chapter else sorted(_COMPLIANCE_MAP.keys())

        _FRAMEWORK_LABELS = {
            "pci-dss": "PCI-DSS 4.0",
            "iso27001": "ISO 27001:2022",
            "nist-800-53": "NIST SP 800-53 Rev. 5",
        }

        sections: list[str] = []
        for ch in chapters:
            if ch not in _COMPLIANCE_MAP:
                continue
            ch_map = _COMPLIANCE_MAP[ch]
            lines = [f"### ASVS {ch}"]
            for fw in frameworks:
                controls = ch_map.get(fw, [])
                if controls:
                    lines.append(f"**{_FRAMEWORK_LABELS.get(fw, fw)}:** {', '.join(controls)}")
            sections.append("\n".join(lines))

        if not sections:
            return f"No compliance mapping found for the given criteria."

        header = f"## Compliance Mapping"
        if asvs_chapter:
            header += f" — ASVS {asvs_chapter.upper()}"
        header += f"\n\n_Mapping ASVS chapters to {', '.join(_FRAMEWORK_LABELS.get(f, f) for f in frameworks)}_\n"
        return header + "\n\n".join(sections)
