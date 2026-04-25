from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from owasp_mcp import db
from owasp_mcp.collectors.cheatsheets import fetch_cheatsheet_content
from owasp_mcp.collectors.top10 import TOP10_2021

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from owasp_mcp.index import IndexManager

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
}

_SOURCE_LABELS: dict[str, str] = {
    "projects": "Projects",
    "asvs": "ASVS 5.0",
    "wstg": "WSTG",
    "top10": "Top 10 2021",
    "cheatsheets": "Cheat Sheets",
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


_FORMATTERS = {
    "projects": _fmt_project,
    "asvs": _fmt_asvs,
    "wstg": _fmt_wstg,
    "top10": _fmt_top10,
    "cheatsheets": _fmt_cheatsheet,
}


def register_tools(mcp: "FastMCP", index_mgr: "IndexManager") -> None:

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
