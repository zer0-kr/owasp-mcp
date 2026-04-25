from __future__ import annotations

import logging
import sys
from typing import Any

from fastmcp import FastMCP

from security_framework_mcp import __version__
from security_framework_mcp.config import get_config
from security_framework_mcp.index import IndexManager
from security_framework_mcp.tools.owasp_tools import register_tools

mcp = FastMCP(
    name="security-framework-mcp",
    instructions=(
        "OWASP MCP server providing unified access to all OWASP projects, "
        "standards, and security guidelines. Tools: search_owasp (cross-source), "
        "list_projects/search_projects/get_project (418+ projects), "
        "get_top10 (Top 10 2021), get_api_top10 (API Security 2023), "
        "get_llm_top10 (LLM Top 10 2025), get_asvs (ASVS 5.0), "
        "get_wstg (WSTG), get_masvs (Mobile MASVS), "
        "get_proactive_controls (defensive controls), "
        "get_cheatsheet (113+ sheets), cross_reference (CWE mapping), "
        "assess_stack (tech stack security assessment), "
        "generate_checklist (security checklist generator). "
        "Prompts: security_review, threat_analysis, compliance_check, "
        "secure_code_review for guided security workflows."
    ),
)


def _register_resources(index_mgr: IndexManager) -> None:
    from security_framework_mcp.collectors.top10 import TOP10_2021
    from security_framework_mcp.collectors.api_top10 import API_TOP10_2023
    from security_framework_mcp.collectors.llm_top10 import LLM_TOP10_2025
    from security_framework_mcp.collectors.proactive_controls import PROACTIVE_CONTROLS_2024

    @mcp.resource("owasp://about")
    def about() -> str:
        info = index_mgr.status()
        return (
            "# Security Framework MCP Server\n\n"
            f"- **Version:** {__version__}\n"
            f"- **Database available:** {'Yes' if info['exists'] else 'No'}\n"
            f"- **Database built:** {info.get('built_at', 'never')}\n"
            f"- **Database path:** `{info['path']}`\n\n"
            "## OWASP Tools (18)\n\n"
            "- `list_projects` / `search_projects` / `get_project` — 418+ projects\n"
            "- `search_owasp` — Cross-source search (17 data sources)\n"
            "- `get_top10` / `get_api_top10` / `get_llm_top10` / `get_mcp_top10`\n"
            "- `get_asvs` / `get_wstg` / `get_masvs`\n"
            "- `get_proactive_controls` / `get_cheatsheet` / `get_cwe`\n"
            "- `cross_reference` / `compliance_map`\n"
            "- `assess_stack` / `generate_checklist`\n\n"
            "## NIST Tools (7)\n\n"
            "- `search_nist` — Search all NIST sources (controls, CSF, publications, glossary, CMVP, NICE)\n"
            "- `get_nist_control` — SP 800-53 Rev. 5 (1,196 controls)\n"
            "- `get_nist_csf` — CSF 2.0 (225 entries)\n"
            "- `get_nist_publication` — 613 publications (SP 800, FIPS, IR, CSWP)\n"
            "- `get_nist_glossary` — Cybersecurity terms\n"
            "- `get_nist_cmvp` — FIPS 140 validated crypto modules\n"
            "- `get_nice_roles` — NICE Workforce Framework roles\n\n"
            "## Security Analysis Tools (4)\n\n"
            "- `assess_mcp_security` — MCP Top 10 assessment\n"
            "- `threat_model` — STRIDE threat modeling\n"
            "- `search_cve` / `get_cve_detail` — Live NVD CVE search\n\n"
            "## Management (2)\n\n"
            "- `update_database` / `database_status`\n\n"
            "## Prompts (4)\n\n"
            "- `security_review` — Guided security review\n"
            "- `threat_analysis` — Threat analysis workflow\n"
            "- `compliance_check` — Compliance assessment\n"
            "- `secure_code_review` — Code security review\n"
        )

    @mcp.resource("owasp://stats")
    def stats() -> str:
        from security_framework_mcp import db
        from pathlib import Path
        info = index_mgr.status()
        if not info["exists"]:
            return "Database not built yet. Call update_database first."
        db_path = Path(info["path"])
        tables = {
            "Projects": "projects", "ASVS 5.0": "asvs", "WSTG": "wstg",
            "Top 10 2021": "top10", "API Top 10 2023": "api_top10",
            "LLM Top 10 2025": "llm_top10", "Proactive Controls": "proactive_controls",
            "MASVS": "masvs", "Cheat Sheets": "cheatsheets",
        }
        lines = ["# OWASP MCP Database Statistics\n"]
        total = 0
        for label, table in tables.items():
            _, count = db.get_all(db_path, table, limit=1)
            total += count
            lines.append(f"- **{label}:** {count} records")
        lines.append(f"\n**Total:** {total} records")
        lines.append(f"**DB Size:** {info.get('db_size_bytes', 0):,} bytes")
        lines.append(f"**Built:** {info.get('built_at', 'never')}")
        return "\n".join(lines)

    @mcp.resource("owasp://top10/2021")
    def top10_resource() -> str:
        lines = ["# OWASP Top 10 — 2021\n"]
        for item in TOP10_2021:
            lines.append(f"## {item['id']} — {item['name']}\n{item['description']}\n")
        return "\n".join(lines)

    @mcp.resource("owasp://api-top10/2023")
    def api_top10_resource() -> str:
        lines = ["# OWASP API Security Top 10 — 2023\n"]
        for item in API_TOP10_2023:
            lines.append(f"## {item['id']} — {item['name']}\n{item['description']}\n")
        return "\n".join(lines)

    @mcp.resource("owasp://llm-top10/2025")
    def llm_top10_resource() -> str:
        lines = ["# OWASP LLM Top 10 — 2025\n"]
        for item in LLM_TOP10_2025:
            lines.append(f"## {item['id']} — {item['name']}\n{item['description']}\n")
        return "\n".join(lines)

    @mcp.resource("owasp://proactive-controls/2024")
    def proactive_controls_resource() -> str:
        lines = ["# OWASP Proactive Controls — 2024\n"]
        for item in PROACTIVE_CONTROLS_2024:
            lines.append(f"## {item['id']} — {item['name']}\n{item['description']}\n")
        return "\n".join(lines)


def _register_prompts() -> None:
    @mcp.prompt()
    def security_review(system_description: str) -> str:
        """Guided security review workflow — analyzes a system against OWASP standards."""
        return (
            f"I need to perform a security review of the following system:\n\n"
            f"{system_description}\n\n"
            f"Please conduct a thorough security assessment using OWASP resources. Follow these steps:\n\n"
            f"1. Use `assess_stack` to identify relevant security domains for the technology stack\n"
            f"2. Use `get_top10` to check for Web Top 10 risks that apply\n"
            f"3. If APIs are involved, use `get_api_top10` to check API-specific risks\n"
            f"4. If AI/LLM is involved, use `get_llm_top10` for LLM-specific risks\n"
            f"5. Use `get_asvs` to identify verification requirements for the relevant chapters\n"
            f"6. Use `get_wstg` to identify test cases that should be executed\n"
            f"7. Use `cross_reference` for any specific CWEs you identify\n"
            f"8. Use `get_cheatsheet` for remediation guidance on identified issues\n\n"
            f"Provide a structured security review report with:\n"
            f"- Executive summary\n"
            f"- Identified risks (with OWASP references)\n"
            f"- Recommended mitigations (with cheat sheet links)\n"
            f"- Testing checklist (WSTG references)"
        )

    @mcp.prompt()
    def threat_analysis(system_description: str) -> str:
        """Analyze threats for a given system using OWASP threat intelligence data."""
        return (
            f"Perform a threat analysis for the following system:\n\n"
            f"{system_description}\n\n"
            f"Use OWASP resources to identify threats:\n\n"
            f"1. Use `assess_stack` to identify the security domains\n"
            f"2. For each relevant Top 10 (web, API, LLM), identify applicable threats\n"
            f"3. Use `cross_reference` to map threats to specific CWEs\n"
            f"4. Use `get_wstg` to find test cases that validate each threat\n"
            f"5. Use `get_proactive_controls` to identify defensive measures\n\n"
            f"Output a threat matrix with:\n"
            f"- Threat name and OWASP ID\n"
            f"- Likelihood (High/Medium/Low)\n"
            f"- Impact (High/Medium/Low)\n"
            f"- OWASP control references\n"
            f"- Recommended test cases (WSTG IDs)"
        )

    @mcp.prompt()
    def compliance_check(standard: str, system_description: str) -> str:
        """Check compliance requirements for a given standard against a system."""
        return (
            f"I need to check compliance of the following system against {standard}:\n\n"
            f"{system_description}\n\n"
            f"Use OWASP resources to assess compliance:\n\n"
            f"1. Use `get_asvs` to identify all relevant ASVS requirements\n"
            f"2. Use `get_wstg` to map test procedures for each requirement\n"
            f"3. Use `get_proactive_controls` to identify implementation guidance\n"
            f"4. Use `get_cheatsheet` for specific implementation references\n\n"
            f"Produce a compliance checklist with:\n"
            f"- Requirement ID and description\n"
            f"- Status: Pass / Fail / Not Tested / Not Applicable\n"
            f"- Evidence required\n"
            f"- Remediation guidance (with cheat sheet references)"
        )

    @mcp.prompt()
    def secure_code_review(language: str, code_context: str) -> str:
        """Security-focused code review using OWASP guidelines."""
        return (
            f"Perform a security-focused code review for {language} code:\n\n"
            f"{code_context}\n\n"
            f"Use OWASP resources during the review:\n\n"
            f"1. Check against OWASP Top 10 2021 (`get_top10`) — especially A03 Injection and A01 Access Control\n"
            f"2. Use `get_asvs` for specific verification requirements related to the code\n"
            f"3. Use `cross_reference` for any CWEs you identify in the code\n"
            f"4. Use `get_cheatsheet` for secure coding patterns (e.g., SQL Injection Prevention, XSS Prevention)\n"
            f"5. Use `get_proactive_controls` to recommend defensive improvements\n\n"
            f"Report:\n"
            f"- Vulnerabilities found (with CWE IDs and OWASP references)\n"
            f"- Risk severity (Critical/High/Medium/Low)\n"
            f"- Secure code alternatives (with cheat sheet references)\n"
            f"- ASVS requirements that should be verified"
        )


def main() -> None:
    import os
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    config = get_config()
    index_mgr = IndexManager(config)

    from security_framework_mcp.nvd import NVDClient
    from security_framework_mcp.kev import KEVClient
    nvd_api_key = os.environ.get("NVD_API_KEY")
    nvd_client = NVDClient(api_key=nvd_api_key)
    kev_client = KEVClient(cache_dir=config.data_dir)

    register_tools(mcp, index_mgr, nvd_client=nvd_client, kev_client=kev_client)
    _register_resources(index_mgr)
    _register_prompts()

    mcp.run(transport="stdio")
