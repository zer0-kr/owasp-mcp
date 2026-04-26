#!/usr/bin/env python3
"""100 security practitioner questions against all 41 MCP tools."""

import asyncio
import logging
import os
import sys
import time
import traceback

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)


async def main():
    from security_framework_mcp.tools.owasp_tools import register_tools
    from security_framework_mcp.epss import EPSSClient
    from security_framework_mcp.nvd import NVDClient
    from security_framework_mcp.kev import KEVClient
    from security_framework_mcp.index import IndexManager
    from security_framework_mcp.config import get_config
    from fastmcp import FastMCP

    config = get_config()
    index_mgr = IndexManager(config)
    nvd_client = NVDClient(api_key=os.environ.get("NVD_API_KEY"))
    kev_client = KEVClient(cache_dir=config.data_dir)
    epss_client = EPSSClient()

    mcp = FastMCP("test")
    register_tools(mcp, index_mgr, nvd_client=nvd_client, kev_client=kev_client, epss_client=epss_client)

    # Build DB if needed
    if not index_mgr.db_path.exists():
        print("⏳ Building database from sources (first run)...")
        t0 = time.time()
        await index_mgr.ensure_index()
        print(f"✅ Database built in {time.time() - t0:.1f}s\n")
    else:
        print(f"✅ Database exists at {index_mgr.db_path}\n")

    # ── helpers ──────────────────────────────────────────────────────────
    passed = 0
    failed = 0
    skipped = 0
    total = 0
    results_log: list[str] = []

    async def run_test(tc_num: int, description: str, tool_name: str, params: dict,
                       expect_keywords: list[str] | None = None, timeout_s: float = 60,
                       is_api: bool = False):
        nonlocal passed, failed, skipped, total
        total += 1
        tag = f"TC{tc_num:02d}"
        try:
            result = await asyncio.wait_for(
                mcp.call_tool(tool_name, params),
                timeout=timeout_s,
            )
            # result is a list of content items
            text = ""
            if isinstance(result, list):
                for item in result:
                    if hasattr(item, "text"):
                        text += item.text
                    else:
                        text += str(item)
            else:
                text = str(result)

            if not text or len(text.strip()) == 0:
                failed += 1
                msg = f"  ❌ {tag}: {description} — empty response"
                results_log.append(msg)
                print(msg)
                return

            # Check expected keywords (case-insensitive)
            if expect_keywords:
                text_lower = text.lower()
                missing = [kw for kw in expect_keywords if kw.lower() not in text_lower]
                if missing:
                    failed += 1
                    msg = f"  ❌ {tag}: {description} — missing keywords: {missing}"
                    results_log.append(msg)
                    print(msg)
                    return

            passed += 1
            msg = f"  ✅ {tag}: {description}"
            results_log.append(msg)
            print(msg)

        except asyncio.TimeoutError:
            if is_api:
                skipped += 1
                msg = f"  ⏭️  {tag}: {description} — SKIP (timeout)"
                results_log.append(msg)
                print(msg)
            else:
                failed += 1
                msg = f"  ❌ {tag}: {description} — timeout ({timeout_s}s)"
                results_log.append(msg)
                print(msg)

        except Exception as exc:
            err_str = str(exc)
            if is_api and ("rate" in err_str.lower() or "429" in err_str or "403" in err_str):
                skipped += 1
                msg = f"  ⏭️  {tag}: {description} — SKIP (rate limit)"
                results_log.append(msg)
                print(msg)
            else:
                failed += 1
                short = err_str[:120]
                msg = f"  ❌ {tag}: {description} — {short}"
                results_log.append(msg)
                print(msg)

    # ── Group 1: NIST Controls (10 tests) ───────────────────────────────
    print("\n=== Group 1: NIST Controls ===")
    await run_test(1, "get_nist_control id=ac-1", "get_nist_control",
                   {"control_id": "ac-1"}, ["ac-1", "access control"])
    await run_test(2, "get_nist_control id=si-10", "get_nist_control",
                   {"control_id": "si-10"}, ["si-10"])
    await run_test(3, "get_nist_control baseline=LOW limit=5", "get_nist_control",
                   {"baseline": "LOW", "limit": 5}, ["LOW"])
    await run_test(4, "get_nist_control baseline=HIGH family=ac limit=5", "get_nist_control",
                   {"baseline": "HIGH", "family": "ac", "limit": 5}, ["ac"])
    await run_test(5, "get_nist_control id=ac-1 include_assessment", "get_nist_control",
                   {"control_id": "ac-1", "include_assessment": True}, ["ac-1"])
    await run_test(6, "search_nist: access control", "search_nist",
                   {"query": "access control"}, ["access"])
    await run_test(7, "search_nist: encryption", "search_nist",
                   {"query": "encryption"}, ["encrypt"])
    await run_test(8, "get_nist_csf function_id=PR", "get_nist_csf",
                   {"function_id": "PR"}, ["PR"])
    await run_test(9, "get_nist_glossary term=risk", "get_nist_glossary",
                   {"term": "risk"}, ["risk"])
    await run_test(10, "get_nist_rmf step=ASSESS", "get_nist_rmf",
                   {"step": "ASSESS"}, ["ASSESS"])

    # ── Group 2: OWASP Core (10 tests) ──────────────────────────────────
    print("\n=== Group 2: OWASP Core ===")
    await run_test(11, "get_top10 id=A01:2021", "get_top10",
                   {"id": "A01:2021"}, ["A01:2021", "Broken Access Control"])
    await run_test(12, "get_api_top10 id=API1:2023", "get_api_top10",
                   {"id": "API1:2023"}, ["API1:2023"])
    await run_test(13, "get_llm_top10 id=LLM01:2025", "get_llm_top10",
                   {"id": "LLM01:2025"}, ["LLM01:2025"])
    await run_test(14, "get_mcp_top10 id=MCP01:2025", "get_mcp_top10",
                   {"id": "MCP01:2025"}, ["MCP01:2025"])
    await run_test(15, "get_proactive_controls id=C1", "get_proactive_controls",
                   {"id": "C1"}, ["C1"])
    await run_test(16, "get_asvs chapter=V4 limit=5", "get_asvs",
                   {"chapter": "V4", "limit": 5}, ["ASVS"])
    await run_test(17, "get_wstg category=WSTG-INPV limit=5", "get_wstg",
                   {"category": "WSTG-INPV", "limit": 5}, ["WSTG"])
    await run_test(18, "get_masvs category=MASVS-STORAGE", "get_masvs",
                   {"category": "MASVS-STORAGE"}, ["MASVS"])
    await run_test(19, "get_cheatsheet name=Authentication", "get_cheatsheet",
                   {"name": "Authentication"}, ["authentication"])
    await run_test(20, "list_projects level=flagship limit=5", "list_projects",
                   {"level": "flagship", "limit": 5}, ["Projects"])

    # ── Group 3: CWE & Vulnerability (10 tests) ─────────────────────────
    print("\n=== Group 3: CWE & Vulnerability ===")
    await run_test(21, "get_cwe id=CWE-79 (XSS)", "get_cwe",
                   {"id": "CWE-79"}, ["CWE-79"])
    await run_test(22, "get_cwe id=89 (SQL Injection)", "get_cwe",
                   {"id": "89"}, ["CWE-89"])
    await run_test(23, "get_cwe id=CWE-601 (Open Redirect)", "get_cwe",
                   {"id": "CWE-601"}, ["CWE-601"])
    await run_test(24, "get_cwe id=CWE-312 (Cleartext Storage)", "get_cwe",
                   {"id": "CWE-312"}, ["CWE-312"])
    await run_test(25, "cross_reference cwe=CWE-79", "cross_reference",
                   {"cwe": "CWE-79"}, ["CWE-79"])
    await run_test(26, "cross_reference cwe=CWE-89", "cross_reference",
                   {"cwe": "CWE-89"}, ["CWE-89"])
    # NVD API calls — 7s delay between
    await run_test(27, "search_cve keyword=log4j", "search_cve",
                   {"keyword": "log4j", "limit": 3}, ["CVE"], timeout_s=30, is_api=True)
    await asyncio.sleep(7)
    await run_test(28, "get_cve_detail CVE-2021-44228", "get_cve_detail",
                   {"cve_id": "CVE-2021-44228"}, ["CVE-2021-44228"], timeout_s=30, is_api=True)
    await asyncio.sleep(7)
    # KEV calls
    await run_test(29, "search_kev cve_id=CVE-2021-44228", "search_kev",
                   {"cve_id": "CVE-2021-44228"}, ["CVE-2021-44228"], timeout_s=30, is_api=True)
    await run_test(30, "search_kev vendor=Microsoft limit=5", "search_kev",
                   {"vendor": "Microsoft", "limit": 5}, ["Microsoft"], timeout_s=30, is_api=True)

    # ── Group 4: CAPEC Attack Patterns (10 tests) ───────────────────────
    print("\n=== Group 4: CAPEC Attack Patterns ===")
    await run_test(31, "get_attack_pattern id=CAPEC-62", "get_attack_pattern",
                   {"id": "CAPEC-62"}, ["CAPEC-62"])
    await run_test(32, "get_attack_pattern id=66", "get_attack_pattern",
                   {"id": "66"}, ["CAPEC-66"])
    await run_test(33, "get_attack_pattern cwe=CWE-79", "get_attack_pattern",
                   {"cwe": "CWE-79"}, ["CWE-79"])
    await run_test(34, "get_attack_pattern cwe=CWE-89", "get_attack_pattern",
                   {"cwe": "CWE-89"}, ["CWE-89"])
    await run_test(35, "get_attack_pattern query=authentication bypass", "get_attack_pattern",
                   {"query": "authentication bypass"}, ["CAPEC"])
    await run_test(36, "get_attack_pattern query=buffer overflow", "get_attack_pattern",
                   {"query": "buffer overflow"}, ["CAPEC"])
    await run_test(37, "get_attack_pattern query=SQL injection", "get_attack_pattern",
                   {"query": "SQL injection"}, ["CAPEC"])
    await run_test(38, "get_attack_pattern query=cross-site", "get_attack_pattern",
                   {"query": "cross-site"}, ["CAPEC"])
    await run_test(39, "get_attack_pattern query=privilege escalation", "get_attack_pattern",
                   {"query": "privilege escalation"}, ["CAPEC"])
    await run_test(40, "get_attack_pattern query=phishing", "get_attack_pattern",
                   {"query": "phishing"}, ["CAPEC"])

    # ── Group 5: Compliance Mapping (10 tests) ──────────────────────────
    print("\n=== Group 5: Compliance Mapping ===")
    await run_test(41, "compliance_map framework=all asvs_chapter=V4", "compliance_map",
                   {"framework": "all", "asvs_chapter": "V4"}, ["V4"])
    await run_test(42, "compliance_map framework=pci-dss asvs_chapter=V3", "compliance_map",
                   {"framework": "pci-dss", "asvs_chapter": "V3"}, ["PCI"])
    await run_test(43, "compliance_map framework=iso27001", "compliance_map",
                   {"framework": "iso27001"}, ["ISO"])
    await run_test(44, "nist_compliance_map family=AC", "nist_compliance_map",
                   {"family": "AC"}, ["Access Control"])
    await run_test(45, "nist_compliance_map family=SI target=pci-dss", "nist_compliance_map",
                   {"family": "SI", "target_framework": "pci-dss"}, ["PCI"])
    await run_test(46, "nist_compliance_map target=iso27001", "nist_compliance_map",
                   {"target_framework": "iso27001"}, ["ISO"])
    await run_test(47, "lookup_compliance requirement=8.3", "lookup_compliance",
                   {"requirement": "8.3"}, ["8.3"])
    await run_test(48, "lookup_compliance requirement=A.5.15", "lookup_compliance",
                   {"requirement": "A.5.15"}, ["A.5.15"])
    await run_test(49, "lookup_compliance requirement=PCI-DSS 7.1", "lookup_compliance",
                   {"requirement": "PCI-DSS 7.1"}, ["7.1"])
    await run_test(50, "lookup_compliance requirement=ISO27001 A.8.5", "lookup_compliance",
                   {"requirement": "ISO27001 A.8.5"}, ["A.8.5"])

    # ── Group 6: Triage & EPSS (10 tests) ───────────────────────────────
    print("\n=== Group 6: Triage & EPSS ===")
    await run_test(51, "triage_cve CVE-2021-44228", "triage_cve",
                   {"cve_ids": "CVE-2021-44228"}, ["CVE-2021-44228"], timeout_s=45, is_api=True)
    await asyncio.sleep(7)
    await run_test(52, "triage_cve CVE-2021-44228,CVE-2023-44487", "triage_cve",
                   {"cve_ids": "CVE-2021-44228,CVE-2023-44487"}, ["Triage"], timeout_s=60, is_api=True)
    await asyncio.sleep(7)
    await run_test(53, "triage_cve CVE-2024-3094", "triage_cve",
                   {"cve_ids": "CVE-2024-3094"}, ["CVE-2024-3094"], timeout_s=45, is_api=True)
    await asyncio.sleep(7)
    await run_test(54, "search_kev vendor=Apache limit=5", "search_kev",
                   {"vendor": "Apache", "limit": 5}, ["Apache"], timeout_s=30, is_api=True)
    await run_test(55, "search_kev ransomware_only=True limit=5", "search_kev",
                   {"ransomware_only": True, "limit": 5}, ["KEV"], timeout_s=30, is_api=True)
    await run_test(56, "search_kev date_added_after=2025-01-01 limit=5", "search_kev",
                   {"date_added_after": "2025-01-01", "limit": 5}, ["KEV"], timeout_s=30, is_api=True)
    await run_test(57, "search_kev vendor=Microsoft after=2025-01-01 limit=5", "search_kev",
                   {"vendor": "Microsoft", "date_added_after": "2025-01-01", "limit": 5},
                   ["Microsoft"], timeout_s=30, is_api=True)
    await run_test(58, "search_kev count_only=True", "search_kev",
                   {"count_only": True}, ["KEV"], timeout_s=30, is_api=True)
    await run_test(59, "search_kev vendor=Google count_only=True", "search_kev",
                   {"vendor": "Google", "count_only": True}, ["Google"], timeout_s=30, is_api=True)
    await run_test(60, "search_kev product=Exchange limit=5", "search_kev",
                   {"product": "Exchange", "limit": 5}, ["Exchange"], timeout_s=30, is_api=True)

    # ── Group 7: map_finding (10 tests) ─────────────────────────────────
    print("\n=== Group 7: map_finding ===")
    await run_test(61, "map_finding cwe=CWE-79", "map_finding",
                   {"cwe": "CWE-79"}, ["CWE-79", "Remediation"])
    await run_test(62, "map_finding cwe=CWE-89", "map_finding",
                   {"cwe": "CWE-89"}, ["CWE-89", "Remediation"])
    await run_test(63, "map_finding cwe=CWE-352", "map_finding",
                   {"cwe": "CWE-352"}, ["CWE-352"])
    await run_test(64, "map_finding cwe=CWE-22", "map_finding",
                   {"cwe": "CWE-22"}, ["CWE-22"])
    await run_test(65, "map_finding cwe=CWE-502", "map_finding",
                   {"cwe": "CWE-502"}, ["CWE-502"])
    await run_test(66, "map_finding desc=XSS in login form", "map_finding",
                   {"description": "XSS vulnerability found in login form"}, ["CWE-79"])
    await run_test(67, "map_finding desc=SQL injection in search", "map_finding",
                   {"description": "SQL injection in search parameter"}, ["CWE-89"])
    await run_test(68, "map_finding desc=SSRF internal network", "map_finding",
                   {"description": "SSRF allowing internal network access"}, ["CWE-918"])
    await run_test(69, "map_finding desc=insecure deserialization", "map_finding",
                   {"description": "insecure deserialization"}, ["CWE-502"])
    await run_test(70, "map_finding desc=command injection via upload", "map_finding",
                   {"description": "command injection via file upload"}, ["CWE-78"])

    # ── Group 8: Security Assessment (10 tests) ─────────────────────────
    print("\n=== Group 8: Security Assessment ===")
    await run_test(71, "assess_stack: React/Node/PostgreSQL/REST", "assess_stack",
                   {"stack": "React, Node.js, PostgreSQL, REST API"}, ["Security Assessment"])
    await run_test(72, "assess_stack: Python/Django/MySQL/GraphQL", "assess_stack",
                   {"stack": "Python, Django, MySQL, GraphQL"}, ["Security Assessment"])
    await run_test(73, "generate_checklist web/standard", "generate_checklist",
                   {"project_type": "web", "level": "standard"}, ["Checklist"])
    await run_test(74, "generate_checklist api/comprehensive", "generate_checklist",
                   {"project_type": "api", "level": "comprehensive"}, ["Checklist"])
    await run_test(75, "generate_checklist mobile/basic", "generate_checklist",
                   {"project_type": "mobile", "level": "basic"}, ["Checklist"])
    await run_test(76, "threat_model: Payment API", "threat_model",
                   {"system": "Payment API with JWT auth, PostgreSQL database, Redis cache"},
                   ["STRIDE"])
    await run_test(77, "threat_model: Mobile app biometric", "threat_model",
                   {"system": "Mobile app with biometric auth, REST API, S3 storage"},
                   ["STRIDE"])
    await run_test(78, "assess_mcp_security: shell+no auth", "assess_mcp_security",
                   {"description": "shell execution enabled, no auth, community plugins"},
                   ["MCP Security Assessment"])
    await run_test(79, "threat_model: LLM chatbot RAG (STRIDE)", "threat_model",
                   {"system": "LLM chatbot with RAG, vector database, user file uploads",
                    "methodology": "stride"}, ["STRIDE"])
    await run_test(80, "assess_stack: K8s/Docker/Terraform/Lambda", "assess_stack",
                   {"stack": "Kubernetes, Docker, Terraform, AWS Lambda"},
                   ["Security Assessment"])

    # ── Group 9: NIST Advanced (10 tests) ───────────────────────────────
    print("\n=== Group 9: NIST Advanced ===")
    await run_test(81, "get_nist_pf function_id=CONTROL-P", "get_nist_pf",
                   {"function_id": "CONTROL-P"}, ["Privacy Framework"])
    await run_test(82, "get_nist_publication query=cloud limit=5", "get_nist_publication",
                   {"query": "cloud", "limit": 5}, ["NIST"])
    await run_test(83, "get_nist_cmvp query=AES", "get_nist_cmvp",
                   {"query": "AES"}, ["CMVP"])
    await run_test(84, "get_nice_roles query=analyst", "get_nice_roles",
                   {"query": "analyst"}, ["NICE"])
    await run_test(85, "get_nist_mapping source_id=PR.AA", "get_nist_mapping",
                   {"source_id": "PR.AA"}, ["Mapping"])
    await run_test(86, "get_nist_control family=ia limit=5", "get_nist_control",
                   {"family": "ia", "limit": 5}, ["IA"])
    await run_test(87, "search_nist: zero trust", "search_nist",
                   {"query": "zero trust"}, ["NIST"])
    await run_test(88, "get_nist_csf function_id=DE", "get_nist_csf",
                   {"function_id": "DE"}, ["DE"])
    await run_test(89, "get_nist_control id=cm-6", "get_nist_control",
                   {"control_id": "cm-6"}, ["cm-6"])
    await run_test(90, "get_nist_rmf step=SELECT", "get_nist_rmf",
                   {"step": "SELECT"}, ["SELECT"])

    # ── Group 10: Edge Cases & Misc (10 tests) ──────────────────────────
    print("\n=== Group 10: Edge Cases & Misc ===")
    await run_test(91, "search_owasp: authentication limit=5", "search_owasp",
                   {"query": "authentication", "limit": 5}, ["OWASP"])
    await run_test(92, "search_projects: security testing", "search_projects",
                   {"query": "security testing"}, ["Project"])
    await run_test(93, "get_project name=ZAP", "get_project",
                   {"name": "ZAP"}, ["ZAP"])
    await run_test(94, "database_status (no params)", "database_status",
                   {}, ["Database"])
    await run_test(95, "compliance_map framework=all (no chapter)", "compliance_map",
                   {"framework": "all"}, ["Compliance"])
    await run_test(96, "nist_compliance_map (no params — all families)", "nist_compliance_map",
                   {}, ["NIST"])
    await run_test(97, "lookup_compliance requirement=12.10", "lookup_compliance",
                   {"requirement": "12.10"}, ["12.10"])
    await run_test(98, "get_cwe id=CWE-918 (SSRF)", "get_cwe",
                   {"id": "CWE-918"}, ["CWE-918"])
    await run_test(99, "cross_reference cwe=CWE-352", "cross_reference",
                   {"cwe": "CWE-352"}, ["CWE-352"])
    await run_test(100, "search_owasp: injection limit=10", "search_owasp",
                    {"query": "injection", "limit": 10}, ["OWASP"])

    # ── SUMMARY ─────────────────────────────────────────────────────────
    print("\n" + "=" * 50)
    print("           SUMMARY")
    print("=" * 50)
    print(f"  ✅ Passed:  {passed}")
    print(f"  ❌ Failed:  {failed}")
    print(f"  ⏭️  Skipped: {skipped}")
    print(f"  Total:     {total}")
    print("=" * 50)

    # Tools coverage check
    tools_used = set()
    tool_map = {
        1: "get_nist_control", 2: "get_nist_control", 3: "get_nist_control", 4: "get_nist_control",
        5: "get_nist_control", 6: "search_nist", 7: "search_nist", 8: "get_nist_csf",
        9: "get_nist_glossary", 10: "get_nist_rmf", 11: "get_top10", 12: "get_api_top10",
        13: "get_llm_top10", 14: "get_mcp_top10", 15: "get_proactive_controls", 16: "get_asvs",
        17: "get_wstg", 18: "get_masvs", 19: "get_cheatsheet", 20: "list_projects",
        21: "get_cwe", 22: "get_cwe", 23: "get_cwe", 24: "get_cwe", 25: "cross_reference",
        26: "cross_reference", 27: "search_cve", 28: "get_cve_detail", 29: "search_kev",
        30: "search_kev", 31: "get_attack_pattern", 32: "get_attack_pattern",
        33: "get_attack_pattern", 34: "get_attack_pattern", 35: "get_attack_pattern",
        36: "get_attack_pattern", 37: "get_attack_pattern", 38: "get_attack_pattern",
        39: "get_attack_pattern", 40: "get_attack_pattern", 41: "compliance_map",
        42: "compliance_map", 43: "compliance_map", 44: "nist_compliance_map",
        45: "nist_compliance_map", 46: "nist_compliance_map", 47: "lookup_compliance",
        48: "lookup_compliance", 49: "lookup_compliance", 50: "lookup_compliance",
        51: "triage_cve", 52: "triage_cve", 53: "triage_cve", 54: "search_kev",
        55: "search_kev", 56: "search_kev", 57: "search_kev", 58: "search_kev",
        59: "search_kev", 60: "search_kev", 61: "map_finding", 62: "map_finding",
        63: "map_finding", 64: "map_finding", 65: "map_finding", 66: "map_finding",
        67: "map_finding", 68: "map_finding", 69: "map_finding", 70: "map_finding",
        71: "assess_stack", 72: "assess_stack", 73: "generate_checklist",
        74: "generate_checklist", 75: "generate_checklist", 76: "threat_model",
        77: "threat_model", 78: "assess_mcp_security", 79: "threat_model",
        80: "assess_stack", 81: "get_nist_pf", 82: "get_nist_publication",
        83: "get_nist_cmvp", 84: "get_nice_roles", 85: "get_nist_mapping",
        86: "get_nist_control", 87: "search_nist", 88: "get_nist_csf",
        89: "get_nist_control", 90: "get_nist_rmf", 91: "search_owasp",
        92: "search_projects", 93: "get_project", 94: "database_status",
        95: "compliance_map", 96: "nist_compliance_map", 97: "lookup_compliance",
        98: "get_cwe", 99: "cross_reference", 100: "search_owasp",
    }
    for tc_num, tool in tool_map.items():
        tools_used.add(tool)

    # Not tested: update_database (destructive), read_publication (downloads PDF)
    all_tools = {
        "update_database", "database_status", "list_projects", "search_projects",
        "get_project", "search_owasp", "get_top10", "get_asvs", "get_wstg",
        "get_cheatsheet", "cross_reference", "get_api_top10", "get_llm_top10",
        "get_proactive_controls", "get_masvs", "assess_stack", "generate_checklist",
        "read_publication", "get_nist_mapping", "search_kev", "search_nist",
        "get_nist_control", "get_nist_csf", "get_nist_glossary", "get_nist_publication",
        "get_nist_cmvp", "get_nice_roles", "get_nist_pf", "get_nist_rmf",
        "search_cve", "get_cve_detail", "get_mcp_top10", "assess_mcp_security",
        "threat_model", "get_cwe", "compliance_map", "nist_compliance_map",
        "lookup_compliance", "triage_cve", "map_finding", "get_attack_pattern",
    }
    untested = all_tools - tools_used
    print(f"\n  Tools tested: {len(tools_used)}/{len(all_tools)}")
    if untested:
        print(f"  Not tested:  {', '.join(sorted(untested))}")
        print(f"  (update_database=destructive, read_publication=downloads PDF)")
    else:
        print(f"  All tools covered! ✅")


if __name__ == "__main__":
    t_start = time.time()
    asyncio.run(main())
    print(f"\n  Total time: {time.time() - t_start:.1f}s")
