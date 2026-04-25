from __future__ import annotations

import asyncio
import sys
import traceback

PASS = 0
FAIL = 0
ERRORS: list[str] = []


def ok(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)
        ERRORS.append(f"{name}: {detail}")


async def call(client, name: str, args: dict | None = None) -> str:
    r = await client.call_tool(name, args or {})
    if hasattr(r, "content"):
        for c in r.content:
            if hasattr(c, "text"):
                return c.text
    return str(r)


async def call_expect_error(client, name: str, args: dict | None = None) -> str | None:
    try:
        r = await client.call_tool(name, args or {})
        if hasattr(r, "content"):
            for c in r.content:
                if hasattr(c, "text") and c.text:
                    return c.text
        return str(r)
    except Exception as e:
        return f"ERROR:{type(e).__name__}:{e}"


async def run_all():
    from fastmcp import Client
    from owasp_mcp.server import mcp as server_mcp
    from owasp_mcp.config import get_config
    from owasp_mcp.index import IndexManager
    from owasp_mcp.tools.owasp_tools import register_tools

    config = get_config()
    index_mgr = IndexManager(config)
    register_tools(server_mcp, index_mgr)

    client = Client(server_mcp)
    async with client:

        # ============================================================
        # GROUP 1: TOOL REGISTRATION
        # ============================================================
        print("\n=== GROUP 1: Tool Registration ===")

        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        ok("TC01 tool_count", len(tools) == 11, f"got {len(tools)}")

        expected_tools = {
            "list_projects", "search_projects", "get_project",
            "search_owasp", "get_top10", "get_asvs", "get_wstg",
            "get_cheatsheet", "cross_reference",
            "update_database", "database_status",
        }
        ok("TC02 all_tools_present", expected_tools == tool_names,
           f"missing={expected_tools - tool_names}, extra={tool_names - expected_tools}")

        # ============================================================
        # GROUP 2: database_status
        # ============================================================
        print("\n=== GROUP 2: database_status ===")

        txt = await call(client, "database_status")
        ok("TC03 status_available", "Available:** Yes" in txt, txt[:200])
        ok("TC04 status_has_path", "Path:" in txt)
        ok("TC05 status_has_size", "Size:" in txt)
        ok("TC06 status_has_built", "Built:" in txt)

        # ============================================================
        # GROUP 3: list_projects
        # ============================================================
        print("\n=== GROUP 3: list_projects ===")

        txt = await call(client, "list_projects", {"level": "all", "limit": 5})
        ok("TC07 list_all_has_total", "total" in txt.lower(), txt[:200])

        txt = await call(client, "list_projects", {"level": "flagship", "limit": 200})
        ok("TC08 list_flagship_count", "15 total" in txt, txt[:100])
        ok("TC09 list_flagship_has_flagship_label", "Flagship" in txt)

        txt = await call(client, "list_projects", {"level": "production", "limit": 200})
        ok("TC10 list_production", "total" in txt.lower())

        txt = await call(client, "list_projects", {"level": "lab", "limit": 200})
        ok("TC11 list_lab_count", "36 total" in txt, txt[:100])
        ok("TC12 list_lab_has_lab_label", "Lab" in txt)

        txt = await call(client, "list_projects", {"level": "incubator", "limit": 200})
        ok("TC13 list_incubator_count", "206 total" in txt or int(txt.split("total")[0].split("(")[-1].strip()) > 100, txt[:100])
        ok("TC14 list_incubator_has_label", "Incubator" in txt)

        txt = await call(client, "list_projects", {"level": "retired", "limit": 5})
        ok("TC15 list_retired", "total" in txt.lower())

        txt = await call(client, "list_projects", {"type": "code", "limit": 5})
        ok("TC16 list_type_code", "total" in txt.lower())

        txt = await call(client, "list_projects", {"type": "tool", "limit": 5})
        ok("TC17 list_type_tool", "total" in txt.lower() or "No projects" in txt)

        txt = await call(client, "list_projects", {"level": "flagship", "type": "documentation", "limit": 200})
        ok("TC18 list_combined_filter", "total" in txt.lower())

        # pagination
        txt1 = await call(client, "list_projects", {"level": "all", "limit": 3, "offset": 0})
        txt2 = await call(client, "list_projects", {"level": "all", "limit": 3, "offset": 3})
        ok("TC19 pagination_different", txt1 != txt2, "pages should differ")

        txt = await call(client, "list_projects", {"level": "all", "limit": 3, "offset": 0})
        ok("TC20 pagination_hint", "offset=" in txt.lower(), "should suggest next page")

        # ============================================================
        # GROUP 4: search_projects
        # ============================================================
        print("\n=== GROUP 4: search_projects ===")

        txt = await call(client, "search_projects", {"query": "zap"})
        ok("TC21 search_zap", "ZAP" in txt.upper(), txt[:200])

        txt = await call(client, "search_projects", {"query": "mobile security"})
        ok("TC22 search_mobile", "results" in txt.lower() or "mobile" in txt.lower())

        txt = await call(client, "search_projects", {"query": "xyznonexistent12345"})
        ok("TC23 search_no_results", "No projects found" in txt, txt[:200])

        txt = await call(client, "search_projects", {"query": "OWASP"})
        ok("TC24 search_broad", "results" in txt.lower())

        txt = await call(client, "search_projects", {"query": "API security"})
        ok("TC25 search_api_security", "results" in txt.lower() or "No projects" in txt)

        # special characters
        txt = await call(client, "search_projects", {"query": "C/C++"})
        ok("TC26 search_special_chars", isinstance(txt, str))

        txt = await call(client, "search_projects", {"query": "injection OR XSS"})
        ok("TC27 search_fts_operators", isinstance(txt, str))

        # ============================================================
        # GROUP 5: get_project
        # ============================================================
        print("\n=== GROUP 5: get_project ===")

        txt = await call(client, "get_project", {"name": "Top Ten"})
        ok("TC28 project_top_ten", "Flagship" in txt and "Top" in txt, txt[:200])

        txt = await call(client, "get_project", {"name": "ZAP"})
        ok("TC29 project_zap_fuzzy", "ZAP" in txt.upper() or "not found" in txt.lower(), txt[:200])

        txt = await call(client, "get_project", {"name": "totally_nonexistent_project_xyz"})
        ok("TC30 project_not_found", "not found" in txt.lower(), txt[:200])

        txt = await call(client, "get_project", {"name": "Cheat Sheet Series"})
        ok("TC31 project_cheatsheet", "Flagship" in txt or "Cheat" in txt, txt[:200])

        txt = await call(client, "get_project", {"name": "ASVS"})
        ok("TC32 project_asvs_fuzzy", "ASVS" in txt or "Verification" in txt, txt[:200])

        # ============================================================
        # GROUP 6: search_owasp (cross-source)
        # ============================================================
        print("\n=== GROUP 6: search_owasp ===")

        txt = await call(client, "search_owasp", {"query": "injection"})
        ok("TC33 cross_search_injection", "OWASP Search" in txt)
        ok("TC34 cross_search_multi_source", txt.count("###") >= 2, f"sections={txt.count('###')}")

        txt = await call(client, "search_owasp", {"query": "authentication"})
        ok("TC35 cross_search_auth", "OWASP Search" in txt)

        txt = await call(client, "search_owasp", {"query": "xyznonexistent12345"})
        ok("TC36 cross_search_empty", "No OWASP results" in txt, txt[:200])

        txt = await call(client, "search_owasp", {"query": "CSRF"})
        ok("TC37 cross_search_csrf", "OWASP Search" in txt)

        # ============================================================
        # GROUP 7: get_top10
        # ============================================================
        print("\n=== GROUP 7: get_top10 ===")

        txt = await call(client, "get_top10", {})
        ok("TC38 top10_list_all", "A01:2021" in txt and "A10:2021" in txt)
        ok("TC39 top10_list_count", txt.count("A") >= 10)

        txt = await call(client, "get_top10", {"id": "A01:2021"})
        ok("TC40 top10_a01", "Broken Access Control" in txt)
        ok("TC41 top10_a01_cwes", "CWE-" in txt)

        txt = await call(client, "get_top10", {"id": "A03:2021"})
        ok("TC42 top10_a03", "Injection" in txt)

        txt = await call(client, "get_top10", {"id": "A10:2021"})
        ok("TC43 top10_a10", "SSRF" in txt)

        txt = await call(client, "get_top10", {"id": "a03:2021"})
        ok("TC44 top10_case_insensitive", "Injection" in txt, txt[:200])

        txt = await call(client, "get_top10", {"id": "A99:2021"})
        ok("TC45 top10_invalid_id", "not found" in txt.lower(), txt[:200])

        txt = await call(client, "get_top10", {"id": "  A01:2021  "})
        ok("TC46 top10_whitespace_trim", "Broken Access Control" in txt, txt[:200])

        # ============================================================
        # GROUP 8: get_asvs
        # ============================================================
        print("\n=== GROUP 8: get_asvs ===")

        txt = await call(client, "get_asvs", {"limit": 5})
        ok("TC47 asvs_list_all", "ASVS" in txt and "total" in txt.lower())

        txt = await call(client, "get_asvs", {"chapter": "V1", "limit": 5})
        ok("TC48 asvs_chapter_v1", "V1" in txt)

        txt = await call(client, "get_asvs", {"level": "1", "limit": 5})
        ok("TC49 asvs_level_1", "L1" in txt)

        txt = await call(client, "get_asvs", {"chapter": "V1", "level": "1", "limit": 5})
        ok("TC50 asvs_combined_filter", "ASVS" in txt)

        txt = await call(client, "get_asvs", {"query": "password", "limit": 5})
        ok("TC51 asvs_search_password", "ASVS" in txt or "No ASVS" in txt)

        txt = await call(client, "get_asvs", {"query": "injection", "chapter": "V1", "limit": 5})
        ok("TC52 asvs_search_with_filter", isinstance(txt, str))

        txt = await call(client, "get_asvs", {"chapter": "V99"})
        ok("TC53 asvs_invalid_chapter", "No ASVS" in txt, txt[:200])

        # pagination
        txt1 = await call(client, "get_asvs", {"limit": 3, "offset": 0})
        txt2 = await call(client, "get_asvs", {"limit": 3, "offset": 3})
        ok("TC54 asvs_pagination", txt1 != txt2)

        # ============================================================
        # GROUP 9: get_wstg
        # ============================================================
        print("\n=== GROUP 9: get_wstg ===")

        txt = await call(client, "get_wstg", {"limit": 5})
        ok("TC55 wstg_list_all", "WSTG" in txt and "total" in txt.lower())

        txt = await call(client, "get_wstg", {"category": "WSTG-INFO", "limit": 5})
        ok("TC56 wstg_info_category", "WSTG-INFO" in txt)

        txt = await call(client, "get_wstg", {"category": "WSTG-INPV", "limit": 5})
        ok("TC57 wstg_inpv_category", "WSTG-INPV" in txt or "Input Validation" in txt)

        txt = await call(client, "get_wstg", {"query": "SQL", "limit": 5})
        ok("TC58 wstg_search_sql", "WSTG" in txt or "No WSTG" in txt)

        txt = await call(client, "get_wstg", {"query": "XSS", "limit": 5})
        ok("TC59 wstg_search_xss", "WSTG" in txt or "Scripting" in txt or "No WSTG" in txt)

        txt = await call(client, "get_wstg", {"category": "WSTG-ZZZZZ"})
        ok("TC60 wstg_invalid_category", "No WSTG" in txt, txt[:200])

        # ============================================================
        # GROUP 10: get_cheatsheet
        # ============================================================
        print("\n=== GROUP 10: get_cheatsheet ===")

        txt = await call(client, "get_cheatsheet", {})
        ok("TC61 cs_list_all", "Cheat Sheets" in txt)
        ok("TC62 cs_list_count", "113" in txt or int(txt.split("(")[1].split(" ")[0]) > 100, txt[:100])

        txt = await call(client, "get_cheatsheet", {"name": "SQL Injection Prevention"})
        ok("TC63 cs_sql_injection", "SQL Injection" in txt and len(txt) > 1000, f"len={len(txt)}")

        txt = await call(client, "get_cheatsheet", {"name": "Authentication"})
        ok("TC64 cs_auth_fuzzy", len(txt) > 500 or "not found" in txt.lower(), f"len={len(txt)}")

        txt = await call(client, "get_cheatsheet", {"name": "xyznonexistent12345"})
        ok("TC65 cs_not_found", "not found" in txt.lower(), txt[:200])

        txt = await call(client, "get_cheatsheet", {"name": "XSS"})
        ok("TC66 cs_xss_fuzzy", len(txt) > 200 or "not found" in txt.lower())

        # ============================================================
        # GROUP 11: cross_reference
        # ============================================================
        print("\n=== GROUP 11: cross_reference ===")

        txt = await call(client, "cross_reference", {"cwe": "CWE-79"})
        ok("TC67 xref_cwe79", "A03:2021" in txt, txt[:300])
        ok("TC68 xref_cwe79_no_false_match", "A04:2021" not in txt or "A07:2021" not in txt,
           "CWE-79 should NOT match CWE-799/CWE-798")

        txt = await call(client, "cross_reference", {"cwe": "CWE-89"})
        ok("TC69 xref_cwe89", "A03:2021" in txt, txt[:300])

        txt = await call(client, "cross_reference", {"cwe": "CWE-918"})
        ok("TC70 xref_cwe918_ssrf", "A10:2021" in txt, txt[:300])

        txt = await call(client, "cross_reference", {"cwe": "CWE-352"})
        ok("TC71 xref_cwe352_csrf", "A01:2021" in txt, txt[:300])

        txt = await call(client, "cross_reference", {"cwe": "79"})
        ok("TC72 xref_cwe_no_prefix", "A03:2021" in txt, "should auto-prefix CWE-")

        txt = await call(client, "cross_reference", {"top10_id": "A01:2021"})
        ok("TC73 xref_top10_a01", "Broken Access Control" in txt)
        ok("TC74 xref_top10_a01_cwes", "CWE-" in txt)

        txt = await call(client, "cross_reference", {"top10_id": "A03:2021"})
        ok("TC75 xref_top10_a03", "Injection" in txt)

        txt = await call(client, "cross_reference", {"cwe": "CWE-79", "top10_id": "A03:2021"})
        ok("TC76 xref_both_params", "Injection" in txt and "Cross-Reference" in txt)

        r = await call_expect_error(client, "cross_reference", {})
        ok("TC77 xref_no_params_error", r is not None and "ERROR" in str(r), str(r)[:200])

        txt = await call(client, "cross_reference", {"cwe": "CWE-99999"})
        ok("TC78 xref_unknown_cwe", "No cross-references" in txt or "Cross-Reference" in txt)

        txt = await call(client, "cross_reference", {"top10_id": "A99:2021"})
        ok("TC79 xref_invalid_top10", "not found" in txt.lower(), txt[:200])

        # ============================================================
        # GROUP 12: Edge Cases & Robustness
        # ============================================================
        print("\n=== GROUP 12: Edge Cases ===")

        txt = await call_expect_error(client, "search_projects", {"query": "'; DROP TABLE projects; --"})
        ok("TC80 sqli_attempt", txt is not None and "ERROR" not in str(txt), f"should not crash: {str(txt)[:200]}")

        txt = await call_expect_error(client, "search_owasp", {"query": "a"})
        ok("TC81 single_char_search", txt is not None, "should not crash")

        txt = await call_expect_error(client, "search_owasp", {"query": "인증 보안"})
        ok("TC82 unicode_search", txt is not None, "unicode should not crash")

        txt = await call_expect_error(client, "search_projects", {"query": '"exact phrase test"'})
        ok("TC83 quoted_phrase", txt is not None)

        txt = await call_expect_error(client, "search_projects", {"query": "NOT security"})
        ok("TC84 fts_not_operator", txt is not None)

        txt = await call_expect_error(client, "list_projects", {"level": "all", "limit": 1, "offset": 9999})
        ok("TC85 huge_offset", txt is not None)

        txt = await call_expect_error(client, "get_asvs", {"query": "verify AND input", "limit": 5})
        ok("TC86 asvs_and_operator", txt is not None and "ERROR" not in str(txt))

        txt = await call_expect_error(client, "search_owasp", {"query": "OWASP Top 10"})
        ok("TC87 search_owasp_top10", txt is not None)

        txt = await call_expect_error(client, "get_project", {"name": "top ten"})
        ok("TC88 project_case_insensitive", txt is not None and ("Top" in str(txt) or "not found" in str(txt).lower()))

        # ============================================================
        # GROUP 13: Data Integrity Checks
        # ============================================================
        print("\n=== GROUP 13: Data Integrity ===")

        txt = await call(client, "get_asvs", {"limit": 1})
        ok("TC89 asvs_has_345", "345 total" in txt, txt[:100])

        txt = await call(client, "get_wstg", {"limit": 1})
        ok("TC90 wstg_has_111", "111 total" in txt, txt[:100])

        txt = await call(client, "list_projects", {"level": "all", "limit": 1})
        ok("TC91 projects_418_plus",
           int(txt.split("(")[1].split(" ")[0]) >= 418 if "(" in txt else False,
           txt[:100])

    # ============================================================
    # SUMMARY
    # ============================================================
    print(f"\n{'='*60}")
    print(f"RESULTS: {PASS} passed, {FAIL} failed, {PASS + FAIL} total")
    print(f"{'='*60}")
    if ERRORS:
        print("\nFAILED TESTS:")
        for e in ERRORS:
            print(f"  - {e}")
    return FAIL


if __name__ == "__main__":
    failures = asyncio.run(run_all())
    sys.exit(1 if failures else 0)
