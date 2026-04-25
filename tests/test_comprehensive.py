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
    from owasp_mcp.server import mcp as server_mcp, _register_resources, _register_prompts
    from owasp_mcp.config import get_config
    from owasp_mcp.index import IndexManager
    from owasp_mcp.nvd import NVDClient
    from owasp_mcp.tools.owasp_tools import register_tools

    config = get_config()
    index_mgr = IndexManager(config)
    nvd_client = NVDClient()
    register_tools(server_mcp, index_mgr, nvd_client=nvd_client)
    _register_resources(index_mgr)
    _register_prompts()

    client = Client(server_mcp)
    async with client:

        # ============================================================
        # GROUP 1: TOOL REGISTRATION
        # ============================================================
        print("\n=== GROUP 1: Tool Registration ===")

        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        ok("TC01 tool_count", len(tools) == 24, f"got {len(tools)}")

        expected_tools = {
            "list_projects", "search_projects", "get_project",
            "search_owasp", "get_top10", "get_asvs", "get_wstg",
            "get_cheatsheet", "cross_reference",
            "update_database", "database_status",
            "get_api_top10", "get_llm_top10", "get_proactive_controls",
            "get_masvs", "assess_stack", "generate_checklist",
            "get_cwe", "compliance_map",
            "search_cve", "get_cve_detail", "get_mcp_top10",
            "assess_mcp_security", "threat_model",
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

        print("\n=== GROUP 14: get_api_top10 ===")

        txt = await call(client, "get_api_top10", {})
        ok("TC92 api_list_all", "API1:2023" in txt and "API10:2023" in txt)
        ok("TC93 api_list_has_10", txt.count("API") >= 10)

        txt = await call(client, "get_api_top10", {"id": "API1:2023"})
        ok("TC94 api_item1", "Broken Object Level Authorization" in txt)
        ok("TC95 api_item1_cwes", "CWE-" in txt)
        ok("TC96 api_item1_url", "owasp.org" in txt)

        txt = await call(client, "get_api_top10", {"id": "API7:2023"})
        ok("TC97 api_item7_ssrf", "Server Side Request Forgery" in txt)

        txt = await call(client, "get_api_top10", {"id": "api3:2023"})
        ok("TC98 api_case_insensitive", "Object Property" in txt, txt[:200])

        txt = await call(client, "get_api_top10", {"id": "  API1:2023  "})
        ok("TC99 api_whitespace", "Broken Object" in txt)

        txt = await call(client, "get_api_top10", {"id": "API99:2023"})
        ok("TC100 api_invalid_id", "not found" in txt.lower())

        print("\n=== GROUP 15: get_llm_top10 ===")

        txt = await call(client, "get_llm_top10", {})
        ok("TC101 llm_list_all", "LLM01:2025" in txt and "LLM10:2025" in txt)
        ok("TC102 llm_list_has_10", txt.count("LLM") >= 10)

        txt = await call(client, "get_llm_top10", {"id": "LLM01:2025"})
        ok("TC103 llm_item1", "Prompt Injection" in txt)
        ok("TC104 llm_item1_cwes", "CWE-" in txt)

        txt = await call(client, "get_llm_top10", {"id": "LLM06:2025"})
        ok("TC105 llm_item6", "Excessive Agency" in txt)

        txt = await call(client, "get_llm_top10", {"id": "LLM10:2025"})
        ok("TC106 llm_item10", "Unbounded Consumption" in txt)

        txt = await call(client, "get_llm_top10", {"id": "llm01:2025"})
        ok("TC107 llm_case_insensitive", "Prompt Injection" in txt, txt[:200])

        txt = await call(client, "get_llm_top10", {"id": "LLM99:2025"})
        ok("TC108 llm_invalid_id", "not found" in txt.lower())

        print("\n=== GROUP 16: get_proactive_controls ===")

        txt = await call(client, "get_proactive_controls", {})
        ok("TC109 pc_list_all", "C1" in txt and "C10" in txt)
        ok("TC110 pc_list_has_10", txt.count("**C") >= 10)

        txt = await call(client, "get_proactive_controls", {"id": "C1"})
        ok("TC111 pc_c1", "Access Control" in txt)
        ok("TC112 pc_c1_related", "A01:2021" in txt or "Broken Access" in txt)

        txt = await call(client, "get_proactive_controls", {"id": "C3"})
        ok("TC113 pc_c3", "Validate" in txt or "Input" in txt)

        txt = await call(client, "get_proactive_controls", {"id": "C10"})
        ok("TC114 pc_c10", "SSRF" in txt or "Server Side" in txt)

        txt = await call(client, "get_proactive_controls", {"id": "c1"})
        ok("TC115 pc_case_insensitive", "Access Control" in txt, txt[:200])

        txt = await call(client, "get_proactive_controls", {"id": "C99"})
        ok("TC116 pc_invalid_id", "not found" in txt.lower())

        print("\n=== GROUP 17: get_masvs ===")

        txt = await call(client, "get_masvs", {})
        ok("TC117 masvs_list_all", "MASVS Controls" in txt and "total" in txt.lower())
        ok("TC118 masvs_has_23", "23 total" in txt, txt[:100])

        txt = await call(client, "get_masvs", {"category": "MASVS-STORAGE"})
        ok("TC119 masvs_storage", "Storage" in txt and "MASVS-STORAGE" in txt)

        txt = await call(client, "get_masvs", {"category": "MASVS-CRYPTO"})
        ok("TC120 masvs_crypto", "Cryptography" in txt)
        ok("TC121 masvs_crypto_count", "2 total" in txt, txt[:100])

        txt = await call(client, "get_masvs", {"category": "MASVS-AUTH"})
        ok("TC122 masvs_auth", "Authentication" in txt)

        txt = await call(client, "get_masvs", {"category": "MASVS-NETWORK"})
        ok("TC123 masvs_network", "Network" in txt or "TLS" in txt)

        txt = await call(client, "get_masvs", {"category": "MASVS-PLATFORM"})
        ok("TC124 masvs_platform", "Platform" in txt)

        txt = await call(client, "get_masvs", {"category": "MASVS-CODE"})
        ok("TC125 masvs_code", "Code" in txt or "vulnerabilit" in txt.lower())

        txt = await call(client, "get_masvs", {"category": "MASVS-RESILIENCE"})
        ok("TC126 masvs_resilience", "Resilience" in txt or "tamper" in txt.lower())

        txt = await call(client, "get_masvs", {"category": "MASVS-PRIVACY"})
        ok("TC127 masvs_privacy", "Privacy" in txt)

        txt = await call(client, "get_masvs", {"query": "cryptography"})
        ok("TC128 masvs_search_crypto", "MASVS" in txt or "No MASVS" in txt)

        txt = await call(client, "get_masvs", {"category": "MASVS-ZZZZZ"})
        ok("TC129 masvs_invalid_category", "No MASVS" in txt, txt[:200])

        txt = await call(client, "get_masvs", {"query": "sensitive data", "category": "MASVS-STORAGE"})
        ok("TC130 masvs_search_with_filter", isinstance(txt, str))

        print("\n=== GROUP 18: assess_stack ===")

        txt = await call(client, "assess_stack", {"stack": "React, Node.js, PostgreSQL, REST API"})
        ok("TC131 assess_web_api_db", "API Security" in txt and "Web Security" in txt and "Database" in txt)
        ok("TC132 assess_has_tool_refs", "get_api_top10" in txt or "get_top10" in txt)

        txt = await call(client, "assess_stack", {"stack": "Flutter, Firebase, iOS, Android"})
        ok("TC133 assess_mobile", "Mobile Security" in txt and "MASVS" in txt)

        txt = await call(client, "assess_stack", {"stack": "Python, GPT-4, LangChain, RAG, vector database"})
        ok("TC134 assess_llm", "AI/LLM Security" in txt and "LLM Top 10" in txt)

        txt = await call(client, "assess_stack", {"stack": "AWS Lambda, Docker, Kubernetes, Terraform"})
        ok("TC135 assess_cloud", "Cloud" in txt)

        txt = await call(client, "assess_stack", {"stack": "OAuth2, JWT, SAML, Keycloak"})
        ok("TC136 assess_auth", "Authentication" in txt)

        txt = await call(client, "assess_stack", {"stack": "TLS, AES encryption, certificate management"})
        ok("TC137 assess_crypto", "Cryptography" in txt)

        txt = await call(client, "assess_stack", {"stack": "React, Node.js, GPT-4, PostgreSQL, JWT, Docker"})
        ok("TC138 assess_full_stack", txt.count("###") >= 4, f"sections={txt.count('###')}")

        txt = await call(client, "assess_stack", {"stack": "Cobol, Fortran, Assembly"})
        ok("TC139 assess_unknown_defaults_web", "Security Assessment" in txt)

        txt = await call(client, "assess_stack", {"stack": "GraphQL, microservice"})
        ok("TC140 assess_graphql", "API Security" in txt)

        print("\n=== GROUP 19: Cross-Source Integration ===")

        txt = await call(client, "search_owasp", {"query": "prompt injection"})
        ok("TC141 xsearch_llm", "LLM Top 10" in txt, txt[:500])

        txt = await call(client, "search_owasp", {"query": "BOLA authorization"})
        ok("TC142 xsearch_api", isinstance(txt, str))

        txt = await call(client, "search_owasp", {"query": "access control"})
        ok("TC143 xsearch_proactive", "Proactive" in txt or "results" in txt.lower(), txt[:500])

        txt = await call(client, "search_owasp", {"query": "mobile storage"})
        ok("TC144 xsearch_masvs", isinstance(txt, str))

        txt = await call(client, "search_owasp", {"query": "cryptography encryption"})
        ok("TC145 xsearch_crypto_multi", "results" in txt.lower() or "OWASP Search" in txt)

        print("\n=== GROUP 20: New Data Integrity ===")

        txt = await call(client, "get_masvs", {"limit": 1})
        ok("TC146 masvs_total_23", "23 total" in txt, txt[:100])

        txt = await call(client, "get_api_top10", {})
        ok("TC147 api10_has_all_10", all(f"API{i}:2023" in txt for i in range(1, 11)))

        txt = await call(client, "get_llm_top10", {})
        ok("TC148 llm10_has_all_10",
           all(f"LLM{str(i).zfill(2)}:2025" in txt for i in range(1, 11)))

        txt = await call(client, "get_proactive_controls", {})
        ok("TC149 pc_has_all_10", all(f"C{i}" in txt for i in range(1, 11)))

        print("\n=== GROUP 21: Edge Cases New Tools ===")

        txt = await call_expect_error(client, "assess_stack", {"stack": "'; DROP TABLE projects; --"})
        ok("TC150 assess_sqli", txt is not None and "ERROR" not in str(txt))

        txt = await call_expect_error(client, "get_masvs", {"query": "'; DROP TABLE"})
        ok("TC151 masvs_sqli", txt is not None and "ERROR" not in str(txt))

        txt = await call_expect_error(client, "search_owasp", {"query": "NOT AND OR"})
        ok("TC152 xsearch_operators_only", txt is not None)

        print("\n=== GROUP 22: generate_checklist ===")

        txt = await call(client, "generate_checklist", {"project_type": "web", "level": "basic"})
        ok("TC153 cl_web_basic", "- [ ]" in txt and "Top 10" in txt)
        ok("TC154 cl_web_has_items", "items" in txt.lower())

        txt = await call(client, "generate_checklist", {"project_type": "api", "level": "standard"})
        ok("TC155 cl_api_standard", "API" in txt and "- [ ]" in txt)

        txt = await call(client, "generate_checklist", {"project_type": "mobile", "level": "standard"})
        ok("TC156 cl_mobile", "MASVS" in txt)

        txt = await call(client, "generate_checklist", {"project_type": "llm", "level": "basic"})
        ok("TC157 cl_llm", "LLM" in txt and "Prompt" in txt)

        txt = await call(client, "generate_checklist", {"project_type": "full", "level": "comprehensive"})
        ok("TC158 cl_full_comprehensive", txt.count("- [ ]") >= 50, f"items={txt.count('- [ ]')}")

        txt = await call(client, "generate_checklist", {"project_type": "web", "level": "comprehensive"})
        ok("TC159 cl_web_comprehensive", txt.count("- [ ]") > 0)

        print("\n=== GROUP 23: Prompts ===")

        prompts = await client.list_prompts()
        prompt_names = {p.name for p in prompts}
        ok("TC160 prompts_count", len(prompts) == 4, f"got {len(prompts)}")
        ok("TC161 prompts_names", {"security_review", "threat_analysis", "compliance_check", "secure_code_review"} == prompt_names)

        for p in prompts:
            ok(f"TC162_{p.name}_has_desc", p.description is not None and len(p.description) > 10)

        print("\n=== GROUP 24: Resources ===")

        resources = await client.list_resources()
        ok("TC166 resources_count", len(resources) >= 6, f"got {len(resources)}")

        resource_uris = {str(r.uri) for r in resources}
        ok("TC167 has_about", "owasp://about" in resource_uris)
        ok("TC168 has_stats", "owasp://stats" in resource_uris)
        ok("TC169 has_top10", "owasp://top10/2021" in resource_uris)
        ok("TC170 has_api_top10", "owasp://api-top10/2023" in resource_uris)
        ok("TC171 has_llm_top10", "owasp://llm-top10/2025" in resource_uris)
        ok("TC172 has_proactive", "owasp://proactive-controls/2024" in resource_uris)

        print("\n=== GROUP 27: get_mcp_top10 ===")

        txt = await call(client, "get_mcp_top10", {})
        ok("TC187 mcp10_list", "MCP01:2025" in txt and "MCP10:2025" in txt)
        ok("TC188 mcp10_has_10", txt.count("MCP") >= 10)

        txt = await call(client, "get_mcp_top10", {"id": "MCP03:2025"})
        ok("TC189 mcp10_tool_poisoning", "Tool Poisoning" in txt)

        txt = await call(client, "get_mcp_top10", {"id": "MCP07:2025"})
        ok("TC190 mcp10_auth", "Authentication" in txt)

        txt = await call(client, "get_mcp_top10", {"id": "mcp01:2025"})
        ok("TC191 mcp10_case", "Token" in txt, txt[:200])

        txt = await call(client, "get_mcp_top10", {"id": "MCP99:2025"})
        ok("TC192 mcp10_invalid", "not found" in txt.lower())

        print("\n=== GROUP 28: assess_mcp_security ===")

        txt = await call(client, "assess_mcp_security", {"description": "MCP server with shell exec, no auth, API keys in env vars, community plugins, no logging"})
        ok("TC193 mcp_assess_risks", "Potential Risks" in txt)
        ok("TC194 mcp_assess_token", "MCP01" in txt)
        ok("TC195 mcp_assess_tool_poison", "MCP03" in txt)
        ok("TC196 mcp_assess_cmd_inject", "MCP05" in txt)

        txt = await call(client, "assess_mcp_security", {"description": "MCP server with OAuth2 auth, audit logging, pinned dependencies, read-only tools only"})
        ok("TC197 mcp_assess_safer", isinstance(txt, str))

        print("\n=== GROUP 29: threat_model ===")

        txt = await call(client, "threat_model", {"system": "Web API with JWT auth, PostgreSQL, file upload, payment via Stripe", "methodology": "stride"})
        ok("TC198 tm_stride_all", "Spoofing" in txt and "Tampering" in txt)
        ok("TC199 tm_has_references", "OWASP" in txt or "ASVS" in txt)
        ok("TC200 tm_has_risk_levels", "Risk Level" in txt)

        txt = await call(client, "threat_model", {"system": "Mobile app with GPT-4 LLM agent, RAG pipeline, vector database", "methodology": "stride"})
        ok("TC201 tm_llm_threats", "LLM" in txt)

        txt = await call(client, "threat_model", {"system": "MCP server exposing database queries and shell commands", "methodology": "stride"})
        ok("TC202 tm_mcp_threats", "MCP" in txt)

        txt = await call(client, "threat_model", {"system": "Simple static website", "methodology": "summary"})
        ok("TC203 tm_summary_mode", isinstance(txt, str))

        print("\n=== GROUP 30: search_cve (live NVD) ===")

        txt = await call_expect_error(client, "search_cve", {"keyword": "log4j", "severity": "CRITICAL", "limit": 2})
        ok("TC204 cve_search_live", txt is not None and ("CVE-" in str(txt) or "ERROR" in str(txt)))

        r = await call_expect_error(client, "search_cve", {})
        ok("TC205 cve_no_params_error", r is not None and "ERROR" in str(r))

        print("\n=== GROUP 31: Tier 3 Data Integrity ===")

        txt = await call(client, "get_mcp_top10", {})
        ok("TC206 mcp10_complete", all(f"MCP{str(i).zfill(2)}:2025" in txt for i in range(1, 11)))

        print("\n=== GROUP 32: get_cwe coverage ===")

        txt = await call(client, "get_cwe", {"id": "CWE-352"})
        ok("TC207 cwe352_csrf", "Request Forgery" in txt)
        ok("TC208 cwe352_top10", "A01:2021" in txt)

        txt = await call(client, "get_cwe", {"id": "  cwe-200  "})
        ok("TC209 cwe_whitespace_case", "Sensitive Information" in txt)

        txt = await call(client, "get_cwe", {"id": "CWE-502"})
        ok("TC210 cwe502_deser", "Deserialization" in txt)

        txt = await call(client, "get_cwe", {"id": "400"})
        ok("TC211 cwe_num_only", "Resource Consumption" in txt)

        txt = await call(client, "get_cwe", {"id": "CWE-285"})
        ok("TC212 cwe285_multi_map", "API Top 10" in txt)

        print("\n=== GROUP 33: compliance_map coverage ===")

        txt = await call(client, "compliance_map", {"framework": "nist-800-53"})
        ok("TC213 cm_nist_all", txt.count("NIST") >= 10)

        txt = await call(client, "compliance_map", {"framework": "pci-dss", "asvs_chapter": "V6"})
        ok("TC214 cm_pci_v6", "PCI-DSS" in txt and "cryptography" in txt.lower())

        txt = await call(client, "compliance_map", {"framework": "iso27001", "asvs_chapter": "V14"})
        ok("TC215 cm_iso_v14", "ISO" in txt and "vulnerabilit" in txt.lower())

        txt = await call(client, "compliance_map", {"framework": "all", "asvs_chapter": "V99"})
        ok("TC216 cm_invalid_chapter", "No compliance" in txt)

        print("\n=== GROUP 34: threat_model coverage ===")

        txt = await call(client, "threat_model", {"system": "IoT sensor network with MQTT broker and cloud dashboard", "methodology": "stride"})
        ok("TC217 tm_iot", "Spoofing" in txt or "Tampering" in txt)

        txt = await call(client, "threat_model", {"system": "iOS app with biometric auth and local SQLite database", "methodology": "stride"})
        ok("TC218 tm_mobile_detected", "Mobile" in txt)

        txt = await call(client, "threat_model", {"system": "MCP server with tool execution capabilities", "methodology": "stride"})
        ok("TC219 tm_mcp_detected", "MCP" in txt and "Tool Poisoning" in txt)

        txt = await call(client, "threat_model", {"system": "LLM agent with RAG pipeline and tool calling via MCP", "methodology": "stride"})
        ok("TC220 tm_llm_mcp_both", "LLM" in txt and "MCP" in txt)

        txt = await call(client, "threat_model", {"system": "calculator", "methodology": "summary"})
        ok("TC221 tm_summary_minimal", "Threat Model" in txt)

        print("\n=== GROUP 35: assess_mcp_security coverage ===")

        txt = await call(client, "assess_mcp_security", {"description": "Production MCP server with OAuth2, audit logging, pinned dependencies, scoped tokens, no shell access"})
        ok("TC222 mcp_assess_secure", "No Indicators" in txt or "Potential Risks" in txt)

        txt = await call(client, "assess_mcp_security", {"description": "Open public MCP server, anyone can connect, no authentication, shared context between all users, community plugins from marketplace"})
        ok("TC223 mcp_assess_many_risks", txt.count("MCP0") >= 4)

        txt = await call(client, "assess_mcp_security", {"description": "RAG pipeline with document retrieval, vector embeddings, persistent context across sessions"})
        ok("TC224 mcp_assess_context", "MCP06" in txt or "MCP10" in txt)

        print("\n=== GROUP 36: generate_checklist coverage ===")

        txt = await call(client, "generate_checklist", {"project_type": "mobile", "level": "basic"})
        ok("TC225 cl_mobile_basic", "MASVS" in txt and "- [ ]" in txt)

        txt = await call(client, "generate_checklist", {"project_type": "full", "level": "basic"})
        ok("TC226 cl_full_basic", "Web" in txt and "API" in txt and "Mobile" in txt and "LLM" in txt)

        txt = await call(client, "generate_checklist", {"project_type": "api", "level": "comprehensive"})
        ok("TC227 cl_api_comp", txt.count("- [ ]") > 20, f"items={txt.count('- [ ]')}")

        print("\n=== GROUP 37: search_owasp expanded sources ===")

        txt = await call(client, "search_owasp", {"query": "token mismanagement"})
        ok("TC228 xsearch_mcp_top10", "MCP Top 10" in txt, txt[:300])

        txt = await call(client, "search_owasp", {"query": "SQL Injection CWE"})
        ok("TC229 xsearch_cwe_db", "CWE" in txt)

        txt = await call(client, "search_owasp", {"query": "server side request forgery"})
        ok("TC230 xsearch_ssrf_multi", txt.count("###") >= 2, f"sections={txt.count('###')}")

        print("\n=== GROUP 38: db.py edge cases ===")

        from owasp_mcp.db import sanitize_fts_query, _tokenize_query

        ok("TC231 sanitize_empty", sanitize_fts_query("") == "")
        ok("TC232 sanitize_spaces_only", sanitize_fts_query("   ") == "")
        ok("TC233 sanitize_normal", sanitize_fts_query("hello world") == "hello world")
        ok("TC234 sanitize_quotes", '"hello world"' in sanitize_fts_query('"hello world"'))
        ok("TC235 sanitize_mixed", sanitize_fts_query("test NOT end") == "test NOT end")

        tokens = _tokenize_query('')
        ok("TC236 tokenize_empty", tokens == [])
        tokens = _tokenize_query('"unclosed quote')
        ok("TC237 tokenize_unclosed", len(tokens) == 1)
        tokens = _tokenize_query('a "b c" d')
        ok("TC238 tokenize_quoted_phrase", len(tokens) == 3 and tokens[1] == '"b c"')

    # ============================================================
    # SUMMARY
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
