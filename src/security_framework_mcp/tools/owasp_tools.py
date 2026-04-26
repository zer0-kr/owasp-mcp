from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from security_framework_mcp import db
from security_framework_mcp.collectors.cheatsheets import fetch_cheatsheet_content
from security_framework_mcp.collectors.top10 import TOP10_2021
from security_framework_mcp.collectors.api_top10 import API_TOP10_2023
from security_framework_mcp.collectors.llm_top10 import LLM_TOP10_2025
from security_framework_mcp.collectors.proactive_controls import PROACTIVE_CONTROLS_2024

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from security_framework_mcp.index import IndexManager
    from security_framework_mcp.nvd import NVDClient
    from security_framework_mcp.kev import KEVClient
    from security_framework_mcp.epss import EPSSClient

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
    "nist_controls": "nist_controls",
    "nist_csf": "nist_csf",
    "nist_glossary": "nist_glossary",
    "nist_publications": "nist_publications",
    "nist_cmvp": "nist_cmvp",
    "nist_nice": "nist_nice",
    "nist_pf": "nist_pf",
    "nist_rmf": "nist_rmf",
    "capec": "capec",
    "nist_synonyms": "synonyms",
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
    "nist_controls": "NIST SP 800-53",
    "nist_csf": "NIST CSF 2.0",
    "nist_glossary": "NIST Glossary",
    "nist_publications": "NIST Publications",
    "nist_cmvp": "NIST CMVP",
    "nist_nice": "NICE Work Roles",
    "nist_pf": "NIST Privacy Framework 1.0",
    "nist_rmf": "NIST RMF (SP 800-37)",
    "capec": "CAPEC Attack Patterns",
    "nist_synonyms": "NIST Synonyms",
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


def _fmt_capec_detail(row: dict[str, Any], db_path: Any) -> str:
    lines = [f"# {row.get('capec_id', '?')} — {row.get('name', '?')}"]
    sev = row.get("severity") or "N/A"
    lik = row.get("likelihood") or "N/A"
    lines.append(f"\n**Severity:** {sev} | **Likelihood:** {lik}")
    if row.get("description"):
        lines.append(f"\n## Description\n{row['description']}")
    if row.get("prerequisites"):
        lines.append("\n## Prerequisites")
        for p in row["prerequisites"].split("\n"):
            p = p.strip()
            if p:
                lines.append(f"- {p}")
    if row.get("related_cwes"):
        lines.append("\n## Related CWEs")
        for cid in row["related_cwes"].split(","):
            cid = cid.strip()
            if not cid:
                continue
            cwe_rec = db.get_by_id(db_path, "cwes", "cwe_id", cid)
            cwe_name = cwe_rec["name"] if cwe_rec else ""
            if cwe_name:
                lines.append(f"- {cid} — {cwe_name}")
            else:
                lines.append(f"- {cid}")
    if row.get("mitigations"):
        lines.append("\n## Mitigations")
        for m in row["mitigations"].split("\n"):
            m = m.strip()
            if m:
                lines.append(f"- {m}")
    if row.get("url"):
        lines.append(f"\n**Reference:** {row['url']}")
    return "\n".join(lines)


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
    "nist_controls": lambda row: f"**{row.get('id', '?')}** {row.get('title', '')} [{row.get('baselines', '')}]",
    "nist_csf": lambda row: f"**{row.get('id', '?')}** [{row.get('level', '')}] {row.get('title', '')}",
    "nist_glossary": lambda row: f"**{row.get('term', '?')}** — {row.get('definition', '')[:150]}",
    "nist_publications": lambda row: f"**{row.get('id', '?')}** — {row.get('title', '')[:120]}",
    "nist_cmvp": lambda row: f"**Cert #{row.get('cert_number', '?')}** {row.get('vendor', '')} {row.get('module_name', '')} (Level {row.get('fips_level', '?')})",
    "nist_nice": lambda row: f"**{row.get('id', '?')}** {row.get('name', '')} [{row.get('category', '')}]",
    "nist_pf": lambda row: f"**{row.get('id', '?')}** [{row.get('level', '')}] {row.get('title', '')}",
    "nist_rmf": lambda row: f"**{row.get('step_id', '?')}** {row.get('name', '')} — {row.get('description', '')[:120]}",
    "capec": lambda row: f"**{row.get('capec_id', '?')}** {row.get('name', '')} (Severity: {row.get('severity', 'N/A')})",
    "nist_synonyms": lambda row: f"**{row.get('alias', '?')}** — {row.get('canonical', '')}",
}


def _cwe_in_set(cwes_str: str, target: str) -> bool:
    return target in {c.strip() for c in cwes_str.split(",")}


def register_tools(mcp: "FastMCP", index_mgr: "IndexManager", nvd_client: "NVDClient | None" = None, kev_client: "KEVClient | None" = None, epss_client: "EPSSClient | None" = None) -> None:

    # ── Shared compliance maps (used by compliance_map, nist_compliance_map,
    #    lookup_compliance, and map_finding) ──────────────────────────────────

    _ASVS_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
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

    _NIST_FAMILY_MAP: dict[str, dict[str, str | list[str]]] = {
        "AC": {
            "name": "Access Control",
            "pci-dss": [
                "7.1 (Restrict access by business need to know)",
                "7.2 (Manage access to system components)",
                "7.3 (Access to system components is formally managed)",
                "8.2 (User identification and related accounts managed)",
                "8.3 (Strong authentication for users and administrators)",
                "8.6 (Use of application and system accounts managed)",
            ],
            "iso27001": [
                "A.5.15 (Access control)",
                "A.5.18 (Access rights)",
                "A.8.2 (Privileged access rights)",
                "A.8.3 (Information access restriction)",
                "A.8.4 (Access to source code)",
                "A.8.5 (Secure authentication)",
            ],
        },
        "AT": {
            "name": "Awareness and Training",
            "pci-dss": [
                "12.6 (Security awareness training)",
            ],
            "iso27001": [
                "A.6.3 (Information security awareness, education and training)",
            ],
        },
        "AU": {
            "name": "Audit and Accountability",
            "pci-dss": [
                "10.1 (Logging and monitoring processes defined)",
                "10.2 (Audit logs record user activities and anomalies)",
                "10.3 (Audit logs are protected from destruction)",
                "10.4 (Audit logs are reviewed to identify anomalies)",
                "10.5 (Audit log history is retained)",
                "10.7 (Failures of critical security control systems are detected and reported)",
            ],
            "iso27001": [
                "A.8.15 (Logging)",
                "A.8.17 (Clock synchronization)",
            ],
        },
        "CA": {
            "name": "Assessment, Authorization, and Monitoring",
            "pci-dss": [
                "11.1 (Wireless access points are identified and monitored)",
                "11.3 (Vulnerabilities are identified and addressed via scanning)",
                "11.4 (Penetration testing is performed regularly)",
                "12.4 (PCI DSS compliance is managed)",
            ],
            "iso27001": [
                "A.5.35 (Independent review of information security)",
                "A.5.36 (Compliance with policies, rules and standards)",
            ],
        },
        "CM": {
            "name": "Configuration Management",
            "pci-dss": [
                "1.1 (Network security controls defined and understood)",
                "2.1 (Secure configurations processes defined)",
                "2.2 (System components configured and managed securely)",
            ],
            "iso27001": [
                "A.8.9 (Configuration management)",
                "A.8.19 (Installation of software on operational systems)",
                "A.8.32 (Change management)",
            ],
        },
        "CP": {
            "name": "Contingency Planning",
            "pci-dss": [
                "12.10 (Suspected and confirmed security incidents responded to immediately)",
            ],
            "iso27001": [
                "A.5.29 (Information security during disruption)",
                "A.5.30 (ICT readiness for business continuity)",
                "A.8.13 (Information backup)",
                "A.8.14 (Redundancy of information processing facilities)",
            ],
        },
        "IA": {
            "name": "Identification and Authentication",
            "pci-dss": [
                "8.1 (User identification and related accounts managed)",
                "8.2 (User identification managed throughout the lifecycle)",
                "8.3 (Strong authentication established and managed)",
                "8.4 (Multi-factor authentication implemented)",
                "8.5 (MFA systems configured to prevent misuse)",
            ],
            "iso27001": [
                "A.5.16 (Identity management)",
                "A.5.17 (Authentication information)",
                "A.8.5 (Secure authentication)",
            ],
        },
        "IR": {
            "name": "Incident Response",
            "pci-dss": [
                "12.10 (Suspected and confirmed security incidents responded to immediately)",
            ],
            "iso27001": [
                "A.5.24 (Information security incident management planning and preparation)",
                "A.5.25 (Assessment and decision on information security events)",
                "A.5.26 (Response to information security incidents)",
                "A.5.27 (Learning from information security incidents)",
                "A.5.28 (Collection of evidence)",
            ],
        },
        "MA": {
            "name": "Maintenance",
            "pci-dss": [
                "6.3 (Security vulnerabilities identified and addressed)",
            ],
            "iso27001": [
                "A.7.13 (Equipment maintenance)",
                "A.8.9 (Configuration management)",
            ],
        },
        "MP": {
            "name": "Media Protection",
            "pci-dss": [
                "3.1 (Account data storage is kept to a minimum)",
                "3.5 (PAN is secured wherever it is stored)",
                "9.4 (Media with cardholder data is securely stored, accessed, distributed, and destroyed)",
            ],
            "iso27001": [
                "A.7.10 (Storage media)",
                "A.7.14 (Secure disposal or re-use of equipment)",
            ],
        },
        "PE": {
            "name": "Physical and Environmental Protection",
            "pci-dss": [
                "9.1 (Physical access to cardholder data managed)",
                "9.2 (Physical access controls manage entry into facilities)",
                "9.3 (Physical access for personnel and visitors authorized and managed)",
                "9.5 (POI devices are protected from tampering and substitution)",
            ],
            "iso27001": [
                "A.7.1 (Physical security perimeters)",
                "A.7.2 (Physical entry)",
                "A.7.3 (Securing offices, rooms and facilities)",
                "A.7.4 (Physical security monitoring)",
                "A.7.5 (Protecting against physical and environmental threats)",
            ],
        },
        "PL": {
            "name": "Planning",
            "pci-dss": [
                "12.1 (Information security policy established and maintained)",
                "12.3 (Risks to the cardholder data environment are formally identified and assessed)",
            ],
            "iso27001": [
                "A.5.1 (Policies for information security)",
                "A.5.2 (Information security roles and responsibilities)",
            ],
        },
        "PM": {
            "name": "Program Management",
            "pci-dss": [
                "12.1 (Information security policy established and maintained)",
                "12.4 (PCI DSS compliance is managed)",
                "12.5 (PCI DSS scope documented and validated)",
            ],
            "iso27001": [
                "A.5.1 (Policies for information security)",
                "A.5.4 (Management responsibilities)",
            ],
        },
        "PS": {
            "name": "Personnel Security",
            "pci-dss": [
                "12.7 (Personnel are screened to reduce risks from insider threats)",
            ],
            "iso27001": [
                "A.6.1 (Screening)",
                "A.6.2 (Terms and conditions of employment)",
                "A.6.5 (Responsibilities after termination or change of employment)",
            ],
        },
        "PT": {
            "name": "PII Processing and Transparency",
            "pci-dss": [
                "3.6 (Cryptographic keys used to protect stored account data are secured)",
                "3.7 (Where cryptography is used to protect stored account data, key management covered)",
            ],
            "iso27001": [
                "A.5.34 (Privacy and protection of PII)",
            ],
        },
        "RA": {
            "name": "Risk Assessment",
            "pci-dss": [
                "6.3 (Security vulnerabilities identified and addressed)",
                "12.3 (Risks to the cardholder data environment formally identified and assessed)",
            ],
            "iso27001": [
                "A.5.7 (Threat intelligence)",
                "A.8.8 (Management of technical vulnerabilities)",
            ],
        },
        "SA": {
            "name": "System and Services Acquisition",
            "pci-dss": [
                "6.1 (Secure development processes established)",
                "6.2 (Bespoke and custom software developed securely)",
                "6.4 (Public-facing web applications protected against attacks)",
                "6.5 (Changes to all system components managed securely)",
                "12.8 (Risk to information assets from third-party service providers managed)",
            ],
            "iso27001": [
                "A.5.19 (Information security in supplier relationships)",
                "A.5.20 (Addressing information security within supplier agreements)",
                "A.5.21 (Managing information security in the ICT supply chain)",
                "A.8.25 (Secure development life cycle)",
                "A.8.26 (Application security requirements)",
                "A.8.27 (Secure system architecture and engineering principles)",
            ],
        },
        "SC": {
            "name": "System and Communications Protection",
            "pci-dss": [
                "1.2 (Network security controls configured and maintained)",
                "1.3 (Network access to and from the cardholder data environment restricted)",
                "1.4 (Network connections between trusted and untrusted networks controlled)",
                "4.1 (Strong cryptography protects cardholder data during transmission)",
                "4.2 (PAN is protected with strong cryptography during transmission)",
            ],
            "iso27001": [
                "A.8.20 (Networks security)",
                "A.8.21 (Security of network services)",
                "A.8.22 (Segregation of networks)",
                "A.8.24 (Use of cryptography)",
            ],
        },
        "SI": {
            "name": "System and Information Integrity",
            "pci-dss": [
                "5.1 (Malicious software prevented or detected and addressed)",
                "5.2 (Malicious software prevented or detected and addressed)",
                "5.3 (Anti-malware mechanisms and processes are active and maintained)",
                "5.4 (Anti-phishing mechanisms protect users)",
                "6.3 (Security vulnerabilities identified and addressed)",
                "11.5 (Network intrusions and unexpected file changes detected and responded to)",
            ],
            "iso27001": [
                "A.8.7 (Protection against malware)",
                "A.8.8 (Management of technical vulnerabilities)",
            ],
        },
        "SR": {
            "name": "Supply Chain Risk Management",
            "pci-dss": [
                "12.8 (Risk to information assets from third-party service providers managed)",
                "12.9 (Third-party service providers support PCI DSS compliance of their customers)",
            ],
            "iso27001": [
                "A.5.19 (Information security in supplier relationships)",
                "A.5.20 (Addressing information security within supplier agreements)",
                "A.5.21 (Managing information security in the ICT supply chain)",
                "A.5.22 (Monitoring, review and change management of supplier services)",
                "A.5.23 (Information security for use of cloud services)",
            ],
        },
    }

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
            escaped = name.replace("%", "\\%").replace("_", "\\_")
            conn = db.get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT * FROM projects WHERE lower(name) = lower(?) OR lower(title) LIKE lower(?) ESCAPE '\\'",
                    (name, f"%{escaped}%"),
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
            escaped = name.replace("%", "\\%").replace("_", "\\_")
            conn = db.get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT * FROM cheatsheets WHERE lower(name) LIKE lower(?) ESCAPE '\\'",
                    (f"%{escaped}%",),
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

            matched_top10 = [
                item for item in TOP10_2021
                if _cwe_in_set(item["cwes"], cwe_upper)
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
            except Exception as exc:
                log.debug("ASVS cross-reference search failed: %s", exc)

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
            except Exception as exc:
                log.debug("WSTG cross-reference search failed: %s", exc)

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
        except Exception as exc:
            log.debug("Cheat sheet search in assess_stack failed: %s", exc)

        header = f"## Security Assessment: {stack}\n"
        if not sections:
            return f"{header}\nNo specific recommendations found. Use `search_owasp` to explore."

        return header + "\n\n".join(sections)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def generate_checklist(
        project_type: Annotated[Literal["web", "api", "mobile", "llm", "full"], Field(description="Project type")],
        level: Annotated[Literal["basic", "standard", "comprehensive"], Field(description="Depth")] = "standard",
    ) -> str:
        """Generate a security testing checklist based on project type and depth level."""
        db_path = await index_mgr.ensure_index()
        limit_map = {"basic": 8, "standard": 15, "comprehensive": 30}
        per = limit_map[level]
        secs: list[str] = []
        cnt = 0
        if project_type in ("web", "full"):
            items = [f"- [ ] **{t['id']}** {t['name']}" for t in TOP10_2021[:per]]
            cnt += len(items)
            secs.append("### Web — Top 10 2021\n" + "\n".join(items))
        if project_type in ("api", "full"):
            items = [f"- [ ] **{a['id']}** {a['name']}" for a in API_TOP10_2023[:per]]
            cnt += len(items)
            secs.append("### API — Top 10 2023\n" + "\n".join(items))
        if project_type in ("mobile", "full"):
            from security_framework_mcp.collectors.masvs import MASVS_DATA
            items = []
            for _, _, controls in MASVS_DATA:
                for cid, stmt, _ in controls[:2 if level == "basic" else 99]:
                    items.append(f"- [ ] **{cid}** {stmt}")
                    cnt += 1
            secs.append("### Mobile — MASVS\n" + "\n".join(items[:per]))
        if project_type in ("llm", "full"):
            items = [f"- [ ] **{l['id']}** {l['name']}" for l in LLM_TOP10_2025[:per]]
            cnt += len(items)
            secs.append("### LLM — Top 10 2025\n" + "\n".join(items))
        asvs_lvl = "1" if level == "basic" else "2" if level == "standard" else "3"
        results, _ = db.get_all(db_path, "asvs", filters={"level": asvs_lvl}, limit=per)
        a_items = [f"- [ ] **{r['req_id']}** {r['req_description'][:120]}" for r in results]
        cnt += len(a_items)
        if a_items:
            secs.append(f"### ASVS Level {asvs_lvl}\n" + "\n".join(a_items))
        pc = [f"- [ ] **{p['id']}** {p['name']}" for p in PROACTIVE_CONTROLS_2024[:per]]
        cnt += len(pc)
        secs.append("### Proactive Controls\n" + "\n".join(pc))
        return f"## Checklist: {project_type.upper()} ({level})\n\n_{cnt} items_\n" + "\n\n".join(secs)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True))
    async def read_publication(
        publication_id: Annotated[str, Field(description="Publication ID, e.g. 'SP 800-53'", max_length=100)],
        pages: Annotated[str | None, Field(description="Page range, e.g. '1-5'. Omit for table of contents.")] = None,
    ) -> str:
        """Download and read a NIST publication PDF. Returns table of contents or specific pages as Markdown."""
        db_path = await index_mgr.ensure_index()
        from security_framework_mcp.convert import download_file, convert_pdf_to_markdown, get_pdf_toc

        record = db.get_by_id(db_path, "nist_publications", "id", publication_id.strip())
        if record is None:
            return f"Publication '{publication_id}' not found. Use get_nist_publication to search."

        url = record.get("url", "")
        if not url:
            return f"No URL available for '{publication_id}'."

        doc_dir = index_mgr._config.data_dir / "docs" / publication_id.replace(" ", "_")
        filename = publication_id.replace(" ", "_").replace("/", "_") + ".pdf"
        path = doc_dir / filename

        try:
            await download_file(url, path)
        except Exception as exc:
            raise ToolError(f"Download failed: {exc}") from exc

        try:
            if pages:
                md = convert_pdf_to_markdown(path, pages=pages)
            else:
                md = get_pdf_toc(path)
                md += "\n\n_Use `pages` parameter (e.g. pages='1-5') to read specific content._"
        except Exception as exc:
            raise ToolError(f"PDF conversion failed: {exc}") from exc

        return f"# {record.get('title', publication_id)}\n\n{md}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_mapping(
        source_id: Annotated[str | None, Field(description="Source ID, e.g. 'PR.AA' (CSF category)")] = None,
        target_id: Annotated[str | None, Field(description="Target ID, e.g. 'AC-1' (SP 800-53 control)")] = None,
    ) -> str:
        """Look up CSF 2.0 ↔ SP 800-53 framework mappings."""
        db_path = await index_mgr.ensure_index()

        if not source_id and not target_id:
            raise ToolError("Provide source_id (CSF category) or target_id (800-53 control)")

        conn = db.get_connection(db_path)
        try:
            if source_id:
                rows = conn.execute(
                    "SELECT * FROM nist_mappings WHERE source_id = ? OR source_id LIKE ?",
                    (source_id.upper(), f"{source_id.upper()}%"),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM nist_mappings WHERE lower(target_id) = lower(?)",
                    (target_id,),
                ).fetchall()
            results = [dict(r) for r in rows]
        finally:
            conn.close()

        if not results:
            return f"No mappings found for '{source_id or target_id}'."

        lines = [f"## Framework Mappings\n"]
        for r in results:
            lines.append(f"- **{r['source_framework']} {r['source_id']}** → **{r['target_framework']} {r['target_id']}** ({r.get('relationship', '')})")
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True))
    async def search_kev(
        cve_id: Annotated[str | None, Field(description="Check if a specific CVE is in CISA KEV")] = None,
        vendor: Annotated[str | None, Field(description="Filter by vendor, e.g. 'Microsoft', 'Apache'")] = None,
        product: Annotated[str | None, Field(description="Filter by product, e.g. 'Exchange', 'Log4j'")] = None,
        date_added_after: Annotated[str | None, Field(description="Filter KEVs added after date (YYYY-MM-DD)")] = None,
        date_added_before: Annotated[str | None, Field(description="Filter KEVs added before date (YYYY-MM-DD)")] = None,
        ransomware_only: Annotated[bool, Field(description="Only show KEVs with known ransomware campaign use")] = False,
        count_only: Annotated[bool, Field(description="Just return total KEV count")] = False,
        limit: Annotated[int, Field(ge=1, le=100, description="Max results to return")] = 20,
    ) -> str:
        """Search CISA Known Exploited Vulnerabilities (KEV) catalog with vendor, product, date, and ransomware filters."""
        if kev_client is None:
            raise ToolError("KEV client not configured")

        if cve_id:
            entry = await kev_client.get_kev_entry(cve_id)
            if entry is None:
                return f"**{cve_id.upper()}** is NOT in the CISA KEV catalog."
            lines = [
                f"# {entry.get('cveID', cve_id)} — CISA KEV Entry",
                "",
                f"**Vendor/Product:** {entry.get('vendorProject', '')} — {entry.get('product', '')}",
                f"**Vulnerability:** {entry.get('vulnerabilityName', '')}",
                f"**Date Added:** {entry.get('dateAdded', '')}",
                f"**Due Date:** {entry.get('dueDate', '')}",
                f"**Required Action:** {entry.get('requiredAction', '')}",
                f"**Known Ransomware Use:** {entry.get('knownRansomwareCampaignUse', 'Unknown')}",
            ]
            if entry.get("shortDescription"):
                lines.append(f"\n## Description\n{entry['shortDescription']}")
            return "\n".join(lines)

        has_filter = vendor or product or date_added_after or date_added_before or ransomware_only
        if count_only and not has_filter:
            total = await kev_client.get_kev_count()
            return f"CISA KEV catalog contains **{total}** known exploited vulnerabilities."

        if not has_filter and not count_only:
            raise ToolError("Provide cve_id, filters (vendor/product/date_added_after/date_added_before/ransomware_only), or count_only=true")

        results, total = await kev_client.search_catalog(
            vendor=vendor,
            product=product,
            date_added_after=date_added_after,
            date_added_before=date_added_before,
            ransomware_only=ransomware_only,
            limit=limit,
        )

        if count_only:
            filter_parts = []
            if vendor:
                filter_parts.append(f"vendor={vendor}")
            if product:
                filter_parts.append(f"product={product}")
            if date_added_after:
                filter_parts.append(f"after {date_added_after}")
            if date_added_before:
                filter_parts.append(f"before {date_added_before}")
            if ransomware_only:
                filter_parts.append("ransomware only")
            filter_str = ", ".join(filter_parts)
            return f"**{total}** KEV entries matching: {filter_str}"

        if not results:
            return "No KEV entries found matching the given filters."

        header = f"## CISA KEV Search Results ({total} total"
        if total > limit:
            header += f", showing {limit}"
        header += ")\n"

        lines = [header]
        for entry in results:
            ransomware_flag = " 🔴" if entry.get("knownRansomwareCampaignUse", "").lower() == "known" else ""
            lines.append(
                f"- **{entry.get('cveID', '?')}** — {entry.get('vendorProject', '?')} / "
                f"{entry.get('product', '?')} — {entry.get('vulnerabilityName', '')}"
                f" (added: {entry.get('dateAdded', '?')}){ransomware_flag}"
            )
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_nist(
        query: Annotated[str, Field(description="Search keywords", max_length=500)],
        source: Annotated[
            Literal["controls", "csf", "pf", "rmf", "glossary", "publications", "cmvp", "nice", "all"] | None,
            Field(description="Filter: controls, csf, pf, rmf, glossary, publications, cmvp, nice, or all"),
        ] = "all",
        limit: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> str:
        """Search NIST data: SP 800-53 controls, CSF 2.0, PF 1.0, RMF, publications, glossary, CMVP, and NICE roles."""
        if source is None:
            source = "all"
        db_path = await index_mgr.ensure_index()

        source_map = {
            "controls": ("nist_controls", "NIST SP 800-53"),
            "csf": ("nist_csf", "NIST CSF 2.0"),
            "glossary": ("nist_glossary", "NIST Glossary"),
            "publications": ("nist_publications", "NIST Publications"),
            "cmvp": ("nist_cmvp", "NIST CMVP"),
            "nice": ("nist_nice", "NICE Work Roles"),
            "pf": ("nist_pf", "NIST Privacy Framework 1.0"),
            "rmf": ("nist_rmf", "NIST RMF (SP 800-37)"),
            "synonyms": ("synonyms", "NIST Synonyms"),
        }
        sources = list(source_map.items()) if source == "all" else [(source, source_map[source])]

        sections: list[str] = []
        shown = 0
        for src_key, (table, label) in sources:
            try:
                rows, total = db.search_fts(db_path, table, query, limit=min(5, limit) if source == "all" else limit)
            except Exception:
                continue
            if not rows:
                continue
            shown += len(rows)
            fmt = _FORMATTERS.get(table, lambda r: str(r))
            lines = [f"### {label} ({total} total)"]
            lines.extend(f"- {fmt(row)}" for row in rows)
            sections.append("\n".join(lines))

        if not sections:
            return f"No NIST results found for '{query}'."
        return f"## NIST Search: {query}\n\n_Showing {shown} results_\n\n" + "\n\n".join(sections)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_control(
        control_id: Annotated[str | None, Field(description="Control ID, e.g. 'ac-1'. Omit with baseline to list controls.")] = None,
        baseline: Annotated[
            Literal["LOW", "MODERATE", "HIGH"] | None,
            Field(description="Filter by SP 800-53B baseline level"),
        ] = None,
        family: Annotated[str | None, Field(description="Filter by family ID, e.g. 'ac', 'si'")] = None,
        include_assessment: Annotated[bool, Field(description="Include SP 800-53A assessment objectives and methods")] = False,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
    ) -> str:
        """Get NIST SP 800-53 Rev. 5 controls. Filter by ID, baseline (LOW/MODERATE/HIGH), or family."""
        db_path = await index_mgr.ensure_index()

        if control_id:
            normalized = control_id.strip().lower().replace(" ", "")
            record = db.get_by_id(db_path, "nist_controls", "id", normalized)
            if record is None:
                return f"Control '{control_id}' not found. Try search_nist to find the correct ID."

            lines = [
                f"# {record['id'].upper()} — {record['title']}",
                f"\n**Family:** {record.get('family_name', '?')} ({record.get('family_id', '').upper()})",
            ]
            if record.get("baselines"):
                lines.append(f"**Baselines:** {record['baselines']}")
            if record.get("is_withdrawn"):
                lines.append("**Status:** WITHDRAWN")
            if record.get("statement"):
                lines.append(f"\n## Statement\n{record['statement'][:3000]}")
            if record.get("guidance"):
                lines.append(f"\n## Supplemental Guidance\n{record['guidance'][:3000]}")
            if include_assessment:
                if record.get("assessment_objectives"):
                    lines.append(f"\n## Assessment Objectives (SP 800-53A)\n{record['assessment_objectives'][:2000]}")
                if record.get("assessment_methods"):
                    lines.append(f"\n## Assessment Methods\n{record['assessment_methods'][:2000]}")
            return "\n".join(lines)

        conn = db.get_connection(db_path)
        try:
            where_clauses = []
            params: list = []
            if baseline:
                where_clauses.append("baselines LIKE ?")
                params.append(f"%{baseline}%")
            if family:
                where_clauses.append("family_id = ?")
                params.append(family.strip().lower())
            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            total = conn.execute(f"SELECT count(*) FROM nist_controls{where_sql}", params).fetchone()[0]
            rows = conn.execute(f"SELECT * FROM nist_controls{where_sql} LIMIT ?", [*params, limit]).fetchall()
            results = [dict(r) for r in rows]
        finally:
            conn.close()

        if not results:
            return "No controls found matching criteria."

        header = f"## SP 800-53 Controls"
        if baseline:
            header += f" — {baseline} Baseline"
        if family:
            header += f" — {family.upper()} Family"
        header += f" ({total} total)\n"

        lines = [header]
        for r in results:
            lines.append(f"- **{r['id'].upper()}** {r['title']} [{r.get('baselines', '')}]")
        if total > limit:
            lines.append(f"\n_Showing {limit} of {total}. Use limit parameter for more._")
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_csf(
        function_id: Annotated[
            str | None,
            Field(description="CSF Function: GV, ID, PR, DE, RS, RC. Omit for all."),
        ] = None,
        level: Annotated[
            Literal["function", "category", "subcategory", "all"] | None,
            Field(description="Filter by hierarchy level"),
        ] = "all",
        query: Annotated[str | None, Field(description="Search keywords", max_length=500)] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 30,
    ) -> str:
        """Get NIST Cybersecurity Framework (CSF) 2.0 functions, categories, and subcategories."""
        db_path = await index_mgr.ensure_index()

        if query:
            filters: dict[str, Any] = {}
            if function_id:
                filters["function_id"] = function_id.upper()
            if level and level != "all":
                filters["level"] = level
            try:
                results, total = db.search_fts(db_path, "nist_csf", query, filters=filters, limit=limit)
            except Exception as exc:
                raise ToolError(f"CSF search failed: {exc}") from exc
        else:
            filters = {}
            if function_id:
                filters["function_id"] = function_id.upper()
            if level and level != "all":
                filters["level"] = level
            results, total = db.get_all(db_path, "nist_csf", filters=filters, limit=limit)

        if not results:
            return "No CSF entries found matching your criteria."

        lines = [f"## NIST CSF 2.0 ({total} total)\n"]
        for row in results:
            lvl = row.get("level", "")
            indent = "  " if lvl == "category" else "    " if lvl == "subcategory" else ""
            lines.append(f"{indent}- **{row.get('id', '?')}** [{lvl}] {row.get('title', '')}")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_glossary(
        term: Annotated[str | None, Field(description="Term to look up. Omit to list all.", max_length=200)] = None,
    ) -> str:
        """Look up NIST cybersecurity terms and definitions."""
        db_path = await index_mgr.ensure_index()

        if term is None:
            results, total = db.get_all(db_path, "nist_glossary", limit=100)
            lines = [f"## NIST Glossary ({total} terms)\n"]
            for row in results:
                lines.append(f"- **{row['term']}** ({row.get('source', '')})")
            return "\n".join(lines)

        record = db.get_by_id(db_path, "nist_glossary", "term", term)
        if record is None:
            try:
                results, _ = db.search_fts(db_path, "nist_glossary", term, limit=5)
                if results:
                    lines = [f"## NIST Glossary: \"{term}\"\n"]
                    for row in results:
                        lines.append(f"### {row['term']}\n{row['definition']}\n_Source: {row.get('source', 'N/A')}_\n")
                    return "\n".join(lines)
            except Exception as exc:
                log.debug("Glossary FTS search failed: %s", exc)
            return f"Term '{term}' not found. Use get_nist_glossary() to list all terms."

        return f"# {record['term']}\n\n{record['definition']}\n\n_Source: {record.get('source', 'N/A')}_"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_publication(
        id: Annotated[str | None, Field(description="Publication ID, e.g. 'SP 800-53'. Omit to list all.")] = None,
        series: Annotated[str | None, Field(description="Filter by series: SP, FIPS, IR, CSWP")] = None,
        query: Annotated[str | None, Field(description="Search keywords", max_length=500)] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
    ) -> str:
        """Search or browse NIST cybersecurity publications (SP 800, FIPS, IR, CSWP series)."""
        db_path = await index_mgr.ensure_index()

        if id:
            record = db.get_by_id(db_path, "nist_publications", "id", id.strip())
            if record is None:
                try:
                    results, _ = db.search_fts(db_path, "nist_publications", id.strip(), limit=5)
                    if results:
                        lines = [f"## NIST Publications matching '{id}'\n"]
                        for r in results:
                            lines.append(f"- **{r['id']}** — {r['title']}")
                        return "\n".join(lines)
                except Exception as exc:
                    log.debug("Publication FTS search failed: %s", exc)
                return f"Publication '{id}' not found."
            lines = [
                f"# {record['id']} — {record['title']}",
                f"\n**Series:** {record.get('series', '')} | **Status:** {record.get('status', '')} | **Date:** {record.get('pub_date', '')}",
            ]
            if record.get("abstract"):
                lines.append(f"\n## Abstract\n{record['abstract'][:3000]}")
            if record.get("url"):
                lines.append(f"\n**URL:** {record['url']}")
            return "\n".join(lines)

        if query:
            filters: dict[str, Any] = {}
            if series:
                filters["series"] = series.upper()
            try:
                results, total = db.search_fts(db_path, "nist_publications", query, filters=filters, limit=limit)
            except Exception as exc:
                raise ToolError(f"Publication search failed: {exc}") from exc
        else:
            filters = {}
            if series:
                filters["series"] = series.upper()
            results, total = db.get_all(db_path, "nist_publications", filters=filters, limit=limit)

        if not results:
            return "No NIST publications found matching your criteria."

        lines = [f"## NIST Publications ({total} total)\n"]
        for r in results:
            lines.append(f"- **{r['id']}** [{r.get('series', '')}] — {r['title'][:100]}")
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_cmvp(
        query: Annotated[str | None, Field(description="Search vendor, module, or algorithm", max_length=500)] = None,
        fips_level: Annotated[str | None, Field(description="Filter by FIPS level: 1, 2, or 3")] = None,
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
    ) -> str:
        """Search NIST CMVP (Cryptographic Module Validation Program) validated modules."""
        db_path = await index_mgr.ensure_index()

        if query:
            filters: dict[str, Any] = {}
            if fips_level:
                filters["fips_level"] = fips_level
            try:
                results, total = db.search_fts(db_path, "nist_cmvp", query, filters=filters, limit=limit)
            except Exception as exc:
                raise ToolError(f"CMVP search failed: {exc}") from exc
        else:
            filters = {}
            if fips_level:
                filters["fips_level"] = fips_level
            results, total = db.get_all(db_path, "nist_cmvp", filters=filters, limit=limit)

        if not results:
            return "No CMVP modules found."

        lines = [f"## NIST CMVP Modules ({total} total)\n"]
        for r in results:
            lines.append(f"- **Cert #{r['cert_number']}** {r['vendor']} — {r['module_name']} (Level {r.get('fips_level', '?')}, {r.get('status', '')})")
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nice_roles(
        category: Annotated[str | None, Field(description="Filter by category, e.g. 'Protect and Defend'")] = None,
        query: Annotated[str | None, Field(description="Search keywords", max_length=500)] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 50,
    ) -> str:
        """Browse NICE Cybersecurity Workforce Framework work roles (SP 800-181)."""
        db_path = await index_mgr.ensure_index()

        if query:
            filters: dict[str, Any] = {}
            if category:
                filters["category"] = category
            try:
                results, total = db.search_fts(db_path, "nist_nice", query, filters=filters, limit=limit)
            except Exception as exc:
                raise ToolError(f"NICE search failed: {exc}") from exc
        else:
            filters = {}
            if category:
                filters["category"] = category
            results, total = db.get_all(db_path, "nist_nice", filters=filters, limit=limit)

        if not results:
            return "No NICE work roles found."

        lines = [f"## NICE Work Roles ({total} total)\n"]
        for r in results:
            lines.append(f"- **{r['id']}** {r['name']} [{r['category']}]\n  _{r.get('description', '')[:150]}_")
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_pf(
        function_id: Annotated[str | None, Field(description="PF Function: ID-P, GV-P, CT-P, CM-P, PR-P. Omit for all.")] = None,
        level: Annotated[Literal["function", "category", "subcategory", "all"] | None, Field(description="Filter by level")] = "all",
        limit: Annotated[int, Field(ge=1, le=100)] = 50,
    ) -> str:
        """Get NIST Privacy Framework (PF) 1.0 functions, categories, and subcategories."""
        db_path = await index_mgr.ensure_index()
        filters: dict[str, Any] = {}
        if function_id:
            filters["function_id"] = function_id.upper()
        if level and level != "all":
            filters["level"] = level
        results, total = db.get_all(db_path, "nist_pf", filters=filters, limit=limit)
        if not results:
            return "No Privacy Framework entries found."
        lines = [f"## NIST Privacy Framework 1.0 ({total} total)\n"]
        for row in results:
            lvl = row.get("level", "")
            indent = "  " if lvl == "category" else "    " if lvl == "subcategory" else ""
            lines.append(f"{indent}- **{row.get('id', '?')}** [{lvl}] {row.get('title', '')}")
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_rmf(
        step: Annotated[str | None, Field(description="RMF step: PREPARE, CATEGORIZE, SELECT, IMPLEMENT, ASSESS, AUTHORIZE, MONITOR. Omit for all.")] = None,
    ) -> str:
        """Get NIST SP 800-37 Risk Management Framework (RMF) steps, tasks, and key documents."""
        db_path = await index_mgr.ensure_index()
        if step:
            record = db.get_by_id(db_path, "nist_rmf", "step_id", step.strip().upper())
            if record is None:
                return f"RMF step '{step}' not found. Valid: PREPARE, CATEGORIZE, SELECT, IMPLEMENT, ASSESS, AUTHORIZE, MONITOR."
            return "\n".join([
                f"# RMF Step: {record['name']}",
                f"\n{record['description']}",
                f"\n## Tasks\n{record['tasks']}",
                f"\n## Key Documents\n{record['key_documents']}",
            ])
        results, total = db.get_all(db_path, "nist_rmf", limit=10)
        lines = ["## NIST Risk Management Framework (SP 800-37)\n"]
        for r in results:
            lines.append(f"- **{r['step_id']}** — {r['name']}: {r['description'][:120]}...")
        return "\n".join(lines)

    from security_framework_mcp.collectors.mcp_top10 import MCP_TOP10_2025

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
        lines.append("\n_Note: This assessment is based on keyword analysis of your description. For a comprehensive review, examine each MCP Top 10 item individually using `get_mcp_top10`._")

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

        footer = "\n\n_Note: This threat model is based on keyword analysis. For comprehensive STRIDE analysis, provide detailed architecture documentation and review each category with domain-specific tools._"
        return header + "\n\n".join(sections) + footer

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

        matched_top10 = [i for i in TOP10_2021 if _cwe_in_set(i["cwes"], cwe_id)]
        matched_api = [i for i in API_TOP10_2023 if _cwe_in_set(i["cwes"], cwe_id)]
        matched_llm = [i for i in LLM_TOP10_2025 if _cwe_in_set(i["cwes"], cwe_id)]

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
        frameworks = [framework] if framework != "all" else ["pci-dss", "iso27001", "nist-800-53"]
        chapters = [asvs_chapter.upper()] if asvs_chapter else sorted(_ASVS_COMPLIANCE_MAP.keys())

        _FRAMEWORK_LABELS = {
            "pci-dss": "PCI-DSS 4.0",
            "iso27001": "ISO 27001:2022",
            "nist-800-53": "NIST SP 800-53 Rev. 5",
        }

        sections: list[str] = []
        for ch in chapters:
            if ch not in _ASVS_COMPLIANCE_MAP:
                continue
            ch_map = _ASVS_COMPLIANCE_MAP[ch]
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

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def nist_compliance_map(
        family: Annotated[
            str | None,
            Field(description="SP 800-53 control family ID, e.g. 'AC', 'SI'. Omit to list all families."),
        ] = None,
        target_framework: Annotated[
            Literal["pci-dss", "iso27001", "all"],
            Field(description="Target compliance framework to map NIST controls to"),
        ] = "all",
    ) -> str:
        """Map NIST SP 800-53 Rev. 5 control families to PCI-DSS 4.0 and ISO 27001:2022."""

        _FRAMEWORK_LABELS = {
            "pci-dss": "PCI-DSS 4.0",
            "iso27001": "ISO 27001:2022",
        }

        frameworks = [target_framework] if target_framework != "all" else ["pci-dss", "iso27001"]

        if family:
            family_upper = family.strip().upper()
            if family_upper not in _NIST_FAMILY_MAP:
                valid = ", ".join(sorted(_NIST_FAMILY_MAP.keys()))
                return f"Family '{family}' not found. Valid families: {valid}"
            families = [family_upper]
        else:
            families = sorted(_NIST_FAMILY_MAP.keys())

        sections: list[str] = []
        for fam in families:
            fam_data = _NIST_FAMILY_MAP[fam]
            fam_name = fam_data["name"]
            lines = [f"### {fam} — {fam_name}"]
            for fw in frameworks:
                controls = fam_data.get(fw, [])
                if controls:
                    lines.append(f"**{_FRAMEWORK_LABELS.get(fw, fw)}:** {', '.join(controls)}")
            sections.append("\n".join(lines))

        if not sections:
            return "No compliance mapping found for the given criteria."

        header = "## NIST SP 800-53 Rev. 5 Compliance Mapping"
        if family:
            header += f" — {family.strip().upper()}"
        header += f"\n\n_Mapping SP 800-53 control families to {', '.join(_FRAMEWORK_LABELS.get(f, f) for f in frameworks)}_\n"
        footer = "\n\n_Note: Mappings are based on NIST OLIR crosswalks and Open Security Architecture references. Treat as starting points for detailed gap analysis._"
        return header + "\n\n".join(sections) + footer

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def lookup_compliance(
        requirement: Annotated[str, Field(description="Compliance requirement ID, e.g. 'PCI-DSS 8.3', 'ISO27001 A.5.15', '7.1'", max_length=100)],
        framework: Annotated[
            Literal["pci-dss", "iso27001"] | None,
            Field(description="Source framework. Auto-detected if requirement starts with 'A.' (ISO) or is numeric (PCI)"),
        ] = None,
    ) -> str:
        """Reverse compliance lookup — find NIST SP 800-53 families, ASVS chapters, and related controls from a PCI-DSS or ISO 27001 requirement."""

        _ASVS_CHAPTERS: dict[str, str] = {
            "V1": "Architecture, Design and Threat Modeling",
            "V2": "Authentication",
            "V3": "Session Management",
            "V4": "Access Control",
            "V5": "Validation, Sanitization and Encoding",
            "V6": "Stored Cryptography",
            "V7": "Error Handling and Logging",
            "V8": "Data Protection",
            "V9": "Communication",
            "V10": "Malicious Code",
            "V11": "Business Logic",
            "V12": "Files and Resources",
            "V13": "API and Web Service",
            "V14": "Configuration",
        }

        req = requirement.strip()
        detected_fw = framework

        req_upper = req.upper()
        if "PCI" in req_upper:
            if detected_fw is None:
                detected_fw = "pci-dss"
            for prefix in ["PCI-DSS", "PCI DSS", "PCIDSS", "PCI"]:
                if req_upper.startswith(prefix.upper()):
                    req = req[len(prefix):].lstrip(" -:").strip()
                    break
        elif "ISO" in req_upper:
            if detected_fw is None:
                detected_fw = "iso27001"
            for prefix in ["ISO27001", "ISO 27001", "ISO"]:
                if req_upper.startswith(prefix.upper()):
                    req = req[len(prefix):].lstrip(" -:").strip()
                    break
        elif req.startswith(("A.", "a.")):
            if detected_fw is None:
                detected_fw = "iso27001"
        elif req[:1].isdigit():
            if detected_fw is None:
                detected_fw = "pci-dss"

        fw_keys = [detected_fw] if detected_fw else ["pci-dss", "iso27001"]

        def _entry_num(entry: str) -> str:
            return entry.split("(")[0].strip()

        def _matches(entry: str, query: str) -> bool:
            num = _entry_num(entry).lower()
            q = query.lower()
            return num == q or num.startswith(q + ".")

        matched_entries: list[str] = []
        asvs_chapters: list[str] = []
        nist_families: list[tuple[str, str]] = []
        related_nist_controls: list[str] = []

        for fw_key in fw_keys:
            for chapter, mappings in _ASVS_COMPLIANCE_MAP.items():
                fw_entries = mappings.get(fw_key, [])
                chapter_matched = False
                for entry in fw_entries:
                    if _matches(entry, req):
                        if entry not in matched_entries:
                            matched_entries.append(entry)
                        chapter_matched = True
                if chapter_matched and chapter not in asvs_chapters:
                    asvs_chapters.append(chapter)
                    for ctrl in mappings.get("nist-800-53", []):
                        if ctrl not in related_nist_controls:
                            related_nist_controls.append(ctrl)

            for fam_id, fam_data in _NIST_FAMILY_MAP.items():
                fw_entries = fam_data.get(fw_key, [])
                for entry in fw_entries:
                    if _matches(entry, req):
                        if entry not in matched_entries:
                            matched_entries.append(entry)
                        fam_tuple = (fam_id, str(fam_data["name"]))
                        if fam_tuple not in nist_families:
                            nist_families.append(fam_tuple)

        if nist_families:
            family_ids = {fam_id for fam_id, _ in nist_families}
            for mappings in _ASVS_COMPLIANCE_MAP.values():
                for ctrl in mappings.get("nist-800-53", []):
                    ctrl_prefix = ctrl.split("-")[0]
                    if ctrl_prefix in family_ids and ctrl not in related_nist_controls:
                        related_nist_controls.append(ctrl)

        if not matched_entries:
            pci_examples: set[str] = set()
            iso_examples: set[str] = set()
            for m in _ASVS_COMPLIANCE_MAP.values():
                for e in m.get("pci-dss", []):
                    pci_examples.add(_entry_num(e))
                for e in m.get("iso27001", []):
                    iso_examples.add(_entry_num(e))
            for fam_data in _NIST_FAMILY_MAP.values():
                for e in fam_data.get("pci-dss", []):
                    pci_examples.add(_entry_num(e))
                for e in fam_data.get("iso27001", []):
                    iso_examples.add(_entry_num(e))

            pci_sample = ", ".join(sorted(pci_examples)[:8])
            iso_sample = ", ".join(sorted(iso_examples)[:8])
            return (
                f"## No Match Found\n\n"
                f"Requirement '{requirement}' not found in compliance mappings.\n\n"
                f"**PCI-DSS examples:** {pci_sample}\n"
                f"**ISO 27001 examples:** {iso_sample}"
            )

        fw_label = "PCI-DSS" if detected_fw == "pci-dss" else ("ISO 27001" if detected_fw == "iso27001" else "Compliance")

        lines = [f"## Reverse Compliance Lookup — {fw_label} {req}"]

        if len(matched_entries) == 1:
            lines.append(f"\n_Requirement: {matched_entries[0]}_")
        else:
            lines.append(f"\n_Matched {len(matched_entries)} requirements:_")
            for e in matched_entries:
                lines.append(f"- {e}")

        if nist_families:
            lines.append("\n### NIST SP 800-53 Families")
            for fam_id, fam_name in sorted(nist_families):
                lines.append(f"- **{fam_id}** — {fam_name}")

        if asvs_chapters:
            lines.append("\n### ASVS Chapters")
            for ch in sorted(asvs_chapters):
                ch_name = _ASVS_CHAPTERS.get(ch, "")
                lines.append(f"- **{ch}** — {ch_name}")

        if related_nist_controls:
            lines.append("\n### Related NIST Controls")
            for ctrl in sorted(related_nist_controls):
                lines.append(f"- {ctrl}")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True))
    async def triage_cve(
        cve_ids: Annotated[str, Field(description="Comma-separated CVE IDs, e.g. 'CVE-2024-1234,CVE-2024-5678'", max_length=2000)],
    ) -> str:
        """Triage CVEs with EPSS scores, CVSS severity, and KEV status. Note: makes individual NVD API calls per CVE; expect ~6s/CVE without API key."""
        raw_ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if not raw_ids:
            raise ToolError("No valid CVE IDs provided")
        if len(raw_ids) > 50:
            raise ToolError("Maximum 50 CVE IDs per request")

        epss_scores: dict[str, dict] = {}
        if epss_client is not None:
            try:
                epss_scores = await epss_client.get_scores(raw_ids)
            except Exception as exc:
                log.warning("EPSS batch fetch failed: %s", exc)

        _TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        _TIER_EMOJI = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2"}

        results: list[dict] = []

        for cid in raw_ids:
            cvss_score = 0.0
            cvss_severity = "N/A"
            description = "N/A"
            cwes: list[str] = []

            if nvd_client is not None:
                try:
                    data = await nvd_client.get_cve(cid)
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        cve = vulns[0].get("cve", vulns[0])
                        for desc in cve.get("descriptions", []):
                            if desc.get("lang") == "en":
                                description = desc.get("value", "N/A")
                                break
                        for bucket in ("cvssMetricV31", "cvssMetricV30"):
                            metrics = cve.get("metrics", {}).get(bucket, [])
                            if metrics:
                                cvss_data = metrics[0].get("cvssData", {})
                                cvss_score = float(cvss_data.get("baseScore", 0))
                                cvss_severity = cvss_data.get("baseSeverity", "N/A")
                                break
                        for w in cve.get("weaknesses", []):
                            for d in w.get("description", []):
                                if d.get("lang") == "en" and d.get("value"):
                                    cwes.append(d["value"])
                except Exception as exc:
                    log.warning("NVD fetch failed for %s: %s", cid, exc)

            epss_data = epss_scores.get(cid, {})
            epss_val = epss_data.get("epss", 0.0)
            epss_pct = epss_data.get("percentile", 0.0)

            kev_entry: dict | None = None
            if kev_client is not None:
                try:
                    kev_entry = await kev_client.get_kev_entry(cid)
                except Exception as exc:
                    log.warning("KEV fetch failed for %s: %s", cid, exc)

            if kev_entry is not None:
                tier = "CRITICAL"
            elif epss_val >= 0.7 and cvss_score >= 9.0:
                tier = "CRITICAL"
            elif epss_val >= 0.4 or cvss_score >= 7.0:
                tier = "HIGH"
            elif epss_val >= 0.1 or cvss_score >= 4.0:
                tier = "MEDIUM"
            else:
                tier = "LOW"

            results.append({
                "cve_id": cid,
                "tier": tier,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "epss": epss_val,
                "epss_percentile": epss_pct,
                "kev_entry": kev_entry,
                "cwes": cwes,
                "description": description,
            })

        results.sort(key=lambda r: (_TIER_ORDER.get(r["tier"], 99), -r["cvss_score"], -r["epss"]))

        lines = [f"## CVE Triage Results ({len(results)} CVEs)\n"]
        for r in results:
            emoji = _TIER_EMOJI.get(r["tier"], "")
            lines.append(f"### {emoji} {r['tier']} \u2014 {r['cve_id']}")

            cvss_part = f"{r['cvss_score']} ({r['cvss_severity']})" if r["cvss_score"] > 0 else "N/A"
            epss_part = f"{r['epss'] * 100:.1f}% (percentile: {r['epss_percentile'] * 100:.1f}%)" if r["epss"] > 0 else "N/A"
            lines.append(f"- **CVSS:** {cvss_part} | **EPSS:** {epss_part}")

            if r["kev_entry"] is not None:
                kev = r["kev_entry"]
                lines.append(f"- **KEV Status:** \u26a0\ufe0f In CISA KEV (due: {kev.get('dueDate', 'N/A')})")
            else:
                lines.append("- **KEV Status:** Not in CISA KEV")

            if r["cwes"]:
                lines.append(f"- **CWE:** {', '.join(sorted(set(r['cwes'])))}")

            desc = r["description"]
            if len(desc) > 300:
                desc = desc[:297] + "..."
            lines.append(f"- **Description:** {desc}")
            lines.append("")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def map_finding(
        cwe: Annotated[str | None, Field(description="CWE ID, e.g. 'CWE-79' or '79'")] = None,
        cve: Annotated[str | None, Field(description="CVE ID, e.g. 'CVE-2024-1234'. CWE will be auto-extracted from NVD data")] = None,
        description: Annotated[str | None, Field(description="Free-text finding description for keyword-based matching", max_length=1000)] = None,
    ) -> str:
        """Map a security finding (CWE, CVE, or description) to a complete remediation package: CWE details, OWASP Top 10 / API Top 10 / LLM Top 10 mappings, ASVS requirements, WSTG test cases, cheat sheets, and compliance impact (PCI-DSS 4.0, ISO 27001:2022, NIST 800-53)."""
        _KEYWORD_CWE: dict[str, str] = {
            "cross-site scripting": "79", "cross site scripting": "79", "xss": "79",
            "sql injection": "89", "sqli": "89",
            "server-side request forgery": "918", "server side request forgery": "918", "ssrf": "918",
            "cross-site request forgery": "352", "cross site request forgery": "352", "csrf": "352",
            "xml external entity": "611", "xxe": "611",
            "path traversal": "22", "directory traversal": "22",
            "open redirect": "601",
            "insecure deserialization": "502", "deserialization": "502",
            "os command injection": "78", "command injection": "78",
            "unrestricted file upload": "434", "file upload": "434",
        }

        _CWE_SEARCH_HINTS: dict[str, list[str]] = {
            "79": ["XSS", "cross-site scripting"],
            "89": ["SQL Injection"],
            "918": ["SSRF"],
            "352": ["CSRF"],
            "611": ["XXE"],
            "22": ["path traversal"],
            "601": ["redirect"],
            "502": ["deserialization"],
            "78": ["command injection"],
            "434": ["file upload"],
        }

        cwe_id: str | None = None
        cve_source: str | None = None

        if cwe:
            cwe_id = cwe.strip().upper()
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"
        elif cve:
            if nvd_client is None:
                raise ToolError("NVD client not configured — cannot extract CWE from CVE")
            cve_upper = cve.strip().upper()
            try:
                data = await nvd_client.get_cve(cve_upper)
            except Exception as exc:
                raise ToolError(f"NVD API error: {exc}") from exc
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                raise ToolError(f"CVE '{cve}' not found in NVD")
            cve_data = vulns[0].get("cve", vulns[0])
            cve_source = cve_upper
            for w in cve_data.get("weaknesses", []):
                for d in w.get("description", []):
                    val = d.get("value", "")
                    if d.get("lang") == "en" and val.startswith("CWE-"):
                        cwe_id = val
                        break
                if cwe_id:
                    break
            if not cwe_id:
                raise ToolError(f"No CWE found in {cve_source} weakness data")
        elif description:
            desc_lower = description.lower()
            for keyword, cwe_num in sorted(_KEYWORD_CWE.items(), key=lambda x: -len(x[0])):
                if keyword in desc_lower:
                    cwe_id = f"CWE-{cwe_num}"
                    break
            if not cwe_id:
                raise ToolError("Could not identify a CWE from the description. Try providing a CWE or CVE ID directly.")
        else:
            raise ToolError("Provide at least one of: cwe, cve, or description")

        cwe_num = cwe_id.replace("CWE-", "")
        db_path = await index_mgr.ensure_index()

        cwe_record = db.get_by_id(db_path, "cwes", "cwe_id", cwe_id)
        cwe_name = cwe_record["name"] if cwe_record else "Unknown"
        cwe_desc = cwe_record.get("description", "") if cwe_record else ""

        matched_top10 = [i for i in TOP10_2021 if _cwe_in_set(i["cwes"], cwe_id)]
        matched_api = [i for i in API_TOP10_2023 if _cwe_in_set(i["cwes"], cwe_id)]
        matched_llm = [i for i in LLM_TOP10_2025 if _cwe_in_set(i["cwes"], cwe_id)]

        asvs_results: list[dict[str, Any]] = []
        search_terms = [cwe_num] + _CWE_SEARCH_HINTS.get(cwe_num, [])
        for term in search_terms:
            try:
                results, _ = db.search_fts(db_path, "asvs", term, limit=15)
                if results:
                    asvs_results = results
                    break
            except Exception:
                continue

        wstg_results: list[dict[str, Any]] = []
        for term in search_terms:
            try:
                results, _ = db.search_fts(db_path, "wstg", term, limit=10)
                if results:
                    wstg_results = results
                    break
            except Exception:
                continue

        capec_results: list[dict[str, Any]] = []
        cwe_search = cwe_id.replace('%', '').replace('_', '')
        conn = db.get_connection(db_path)
        try:
            capec_rows = conn.execute(
                "SELECT * FROM capec WHERE ',' || related_cwes || ',' LIKE ? LIMIT 5",
                (f"%,{cwe_search},%",),
            ).fetchall()
            capec_results = [dict(r) for r in capec_rows]
        finally:
            conn.close()

        cs_results: list[dict[str, Any]] = []
        cs_seen: set[str] = set()
        cs_terms = _CWE_SEARCH_HINTS.get(cwe_num, [])
        if cwe_name != "Unknown":
            cs_terms = [cwe_name] + cs_terms
        for term in cs_terms:
            try:
                results, _ = db.search_fts(db_path, "cheatsheets", term, limit=5)
                for r in results:
                    name = r.get("name", "")
                    if name and name not in cs_seen:
                        cs_seen.add(name)
                        cs_results.append(r)
            except Exception:
                continue

        out: list[str] = [f"## Finding Remediation — {cwe_id} ({cwe_name})"]

        if cve_source:
            out.append(f"\n_Auto-extracted from {cve_source}_")

        out.append("\n### CWE Details")
        if cwe_record:
            out.append(f"**{cwe_id}** — {cwe_name}")
            if cwe_desc:
                out.append(cwe_desc[:500])
            if cwe_record.get("url"):
                out.append(f"\n**MITRE URL:** {cwe_record['url']}")
        else:
            out.append(f"**{cwe_id}** — Not found in local database")
            out.append(f"See: https://cwe.mitre.org/data/definitions/{cwe_num}.html")

        out.append("\n### OWASP Top 10 Mapping")
        if matched_top10 or matched_api or matched_llm:
            for item in matched_top10:
                out.append(f"- **{item['id']}** — {item['name']}")
            for item in matched_api:
                out.append(f"- **{item['id']}** — {item['name']} (API Security)")
            for item in matched_llm:
                out.append(f"- **{item['id']}** — {item['name']} (LLM)")
        else:
            out.append("_No direct Top 10 mapping found for this CWE._")

        out.append("\n### ASVS Requirements")
        if asvs_results:
            for row in asvs_results[:10]:
                out.append(f"- {_fmt_asvs(row)}")
        else:
            out.append("_No matching ASVS requirements found._")

        out.append("\n### WSTG Test Cases")
        if wstg_results:
            for row in wstg_results[:10]:
                out.append(f"- {_fmt_wstg(row)}")
        else:
            out.append("_No matching WSTG test cases found._")

        out.append("\n### Attack Patterns (CAPEC)")
        if capec_results:
            for row in capec_results:
                sev = row.get("severity") or "N/A"
                out.append(f"- **{row['capec_id']}** — {row['name']} (Severity: {sev})")
        else:
            out.append("_No CAPEC attack patterns found for this CWE._")

        out.append("\n### Remediation Guidance")
        if cs_results:
            for r in cs_results[:10]:
                out.append(f"- {r.get('name', '?')}")
        else:
            out.append("_No matching cheat sheets found._")

        asvs_chapters: set[str] = set()
        for row in asvs_results:
            ch = row.get("chapter_id", "")
            if ch:
                asvs_chapters.add(ch)
            else:
                req_id = row.get("req_id", "")
                if req_id and "." in req_id:
                    asvs_chapters.add(req_id.split(".")[0])

        out.append("\n### Compliance Impact")
        if asvs_chapters:
            pci: list[str] = []
            iso: list[str] = []
            nist: list[str] = []
            for ch in sorted(asvs_chapters):
                ch_map = _ASVS_COMPLIANCE_MAP.get(ch, {})
                pci.extend(ch_map.get("pci-dss", []))
                iso.extend(ch_map.get("iso27001", []))
                nist.extend(ch_map.get("nist-800-53", []))
            pci = list(dict.fromkeys(pci))
            iso = list(dict.fromkeys(iso))
            nist = list(dict.fromkeys(nist))
            if pci:
                out.append(f"- **PCI-DSS 4.0:** {', '.join(pci)}")
            if iso:
                out.append(f"- **ISO 27001:2022:** {', '.join(iso)}")
            if nist:
                out.append(f"- **NIST 800-53:** {', '.join(nist)}")
            if not pci and not iso and not nist:
                out.append("_No compliance mapping available for matched ASVS chapters._")
        else:
            out.append("_No ASVS chapter matched — compliance mapping not available._")

        return "\n".join(out)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_attack_pattern(
        id: Annotated[str | None, Field(description="CAPEC ID, e.g. 'CAPEC-62' or '62'")] = None,
        cwe: Annotated[str | None, Field(description="Find attack patterns for a CWE, e.g. 'CWE-79'")] = None,
        query: Annotated[str | None, Field(description="Free-text search across attack patterns", max_length=500)] = None,
        limit: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> str:
        """Look up MITRE CAPEC attack patterns by ID, related CWE, or free-text search."""
        db_path = await index_mgr.ensure_index()

        if id is not None:
            capec_id = id.strip().upper()
            if not capec_id.startswith("CAPEC-"):
                capec_id = f"CAPEC-{capec_id}"
            record = db.get_by_id(db_path, "capec", "capec_id", capec_id)
            if record is None:
                return f"Attack pattern '{id}' not found. Use get_attack_pattern with query to search."
            return _fmt_capec_detail(record, db_path)

        if cwe is not None:
            cwe_upper = cwe.strip().upper()
            if not cwe_upper.startswith("CWE-"):
                cwe_upper = f"CWE-{cwe_upper}"
            cwe_upper = cwe_upper.replace('%', '').replace('_', '')
            conn = db.get_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT * FROM capec WHERE ',' || related_cwes || ',' LIKE ? LIMIT ?",
                    (f"%,{cwe_upper},%", limit),
                ).fetchall()
                results = [dict(r) for r in rows]
            finally:
                conn.close()
            if not results:
                return f"No attack patterns found related to {cwe_upper}."
            lines = [f"## Attack Patterns for {cwe_upper} ({len(results)} found)\n"]
            for row in results:
                sev = row.get("severity") or "N/A"
                lines.append(f"- **{row['capec_id']}** — {row['name']} (Severity: {sev})")
            return "\n".join(lines)

        if query is not None:
            try:
                results, total = db.search_fts(db_path, "capec", query, limit=limit)
            except Exception as exc:
                raise ToolError(f"CAPEC search failed: {exc}") from exc
            if not results:
                return f"No attack patterns found for '{query}'."
            lines = [f"## CAPEC Search: {query} ({total} results)\n"]
            for row in results:
                sev = row.get("severity") or "N/A"
                lines.append(f"- **{row['capec_id']}** — {row['name']} (Severity: {sev})")
            return "\n".join(lines)

        raise ToolError("Provide at least one of: id, cwe, or query")
