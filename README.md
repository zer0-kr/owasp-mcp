<p align="center">
  <h1 align="center">owasp-mcp</h1>
  <p align="center">
    <strong>MCP server for unified access to OWASP projects, standards, and security guidelines</strong>
  </p>
  <p align="center">
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
    <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP Compatible"></a>
    <a href="https://owasp.org"><img src="https://img.shields.io/badge/OWASP-data%20source-orange.svg" alt="OWASP"></a>
  </p>
</p>

---

Search and query **1,098+ security data points** through a single MCP interface — **418+ OWASP projects**, **345 ASVS requirements**, **111 WSTG test cases**, **113+ Cheat Sheets**, **Top 10 2021**, **API Security Top 10 2023**, **LLM Top 10 2025**, **MCP Top 10 2025**, **Proactive Controls 2024**, **MASVS**, **38 CWE entries**, and **live NVD/CVE data** — with cross-references, compliance mapping, threat modeling, and MCP security assessment.

## Why owasp-mcp?

Individual OWASP resources are scattered across dozens of repositories with different formats. This server unifies them into one searchable interface:

- Ask "What are the ASVS requirements for authentication?" and get structured results instantly
- Cross-reference a CWE with Top 10 categories, ASVS requirements, and WSTG test cases
- Look up any CWE by ID and see all OWASP mappings automatically
- Map ASVS requirements to PCI-DSS, ISO 27001, and NIST 800-53 for compliance
- Search live NVD for CVE vulnerabilities by keyword, CWE, or severity
- Generate STRIDE-based threat models with OWASP mitigations
- Assess MCP server deployments against the OWASP MCP Top 10
- Generate security checklists tailored to your project type and depth
- Use pre-built prompt templates for guided security reviews and threat analysis
- Browse all 418+ OWASP projects including Lab and Incubator — not just the Flagship ones

No API keys required for local data. NVD API works without a key (rate-limited) or with an optional `NVD_API_KEY` for higher throughput.

## Quick Start

### Install

```bash
pip install git+https://github.com/zer0-kr/owasp-mcp.git
```

### Connect to Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "owasp": {
      "command": "owasp-mcp"
    }
  }
}
```

The local database builds automatically on first run (~5-10 seconds) and refreshes weekly.

### Connect to Other MCP Clients

<details>
<summary><strong>Cursor / Windsurf</strong></summary>

Add to your MCP config:

```json
{
  "owasp": {
    "command": "owasp-mcp"
  }
}
```

</details>

<details>
<summary><strong>OpenCode / CLI</strong></summary>

```json
{
  "mcpServers": {
    "owasp": {
      "type": "stdio",
      "command": "owasp-mcp"
    }
  }
}
```

</details>

<details>
<summary><strong>Docker</strong></summary>

```bash
docker run --rm -i ghcr.io/zer0-kr/owasp-mcp
```

</details>

## Data Sources

| Source | Records | Updated From |
|--------|---------|--------------|
| **Projects** | 418+ | [owasp.github.io/projects.json](https://raw.githubusercontent.com/OWASP/owasp.github.io/main/_data/projects.json) |
| **ASVS 5.0** | 345 | [OWASP/ASVS](https://github.com/OWASP/ASVS) |
| **WSTG** | 111 | [OWASP/wstg](https://github.com/OWASP/wstg) |
| **Top 10 2021** | 10 | [OWASP/Top10](https://github.com/OWASP/Top10) |
| **API Security Top 10 2023** | 10 | [OWASP API Security](https://owasp.org/API-Security/) |
| **LLM Top 10 2025** | 10 | [OWASP GenAI](https://genai.owasp.org/llm-top-10/) |
| **MCP Top 10 2025** | 10 | [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) |
| **Proactive Controls 2024** | 10 | [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) |
| **MASVS** | 23 | [OWASP/owasp-masvs](https://github.com/OWASP/owasp-masvs) |
| **CWE Database** | 38 | [MITRE CWE](https://cwe.mitre.org/) |
| **Cheat Sheets** | 113+ | [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) |
| **NVD/CVE** | Live | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) |

Project levels: **Flagship** (15) · **Production** (12+) · **Lab** (36) · **Incubator** (206+) · Retired

## Tools Reference (24 tools)

### Project Discovery

| Tool | Description |
|------|-------------|
| `list_projects` | Browse all projects. Filter by `level` (flagship/production/lab/incubator) and `type` (code/documentation/tool) |
| `search_projects` | Full-text search across project names, titles, and descriptions |
| `get_project` | Get detailed metadata for a specific project (URL, code repo, description, dates) |

### Standards & Guidelines

| Tool | Description |
|------|-------------|
| `get_asvs` | Query ASVS 5.0 requirements. Filter by `chapter` (V1-V14), `level` (1/2/3), or `query` keyword |
| `get_wstg` | Query WSTG test cases. Filter by `category` (WSTG-INFO, WSTG-INPV, etc.) or `query` keyword |
| `get_top10` | Get Top 10 2021 items with descriptions and CWE mappings |
| `get_api_top10` | Get API Security Top 10 2023 items with CWE mappings |
| `get_llm_top10` | Get LLM Top 10 2025 items — AI/LLM-specific security risks |
| `get_mcp_top10` | Get MCP Top 10 2025 — security risks specific to MCP server deployments |
| `get_proactive_controls` | Get Proactive Controls 2024 — defensive measures for developers |
| `get_masvs` | Query MASVS mobile security controls. Filter by `category` or `query` |
| `get_cheatsheet` | Read a cheat sheet by `name` or list all 113+ available sheets |

### Vulnerability & CWE Lookup

| Tool | Description |
|------|-------------|
| `get_cwe` | Look up any CWE by ID — description, MITRE link, and auto OWASP cross-references across Top 10, API Top 10, and LLM Top 10 |
| `search_cve` | Search the **live NVD** for CVEs by keyword, CWE ID, or CVSS severity |
| `get_cve_detail` | Fetch full CVE details — CVSS score, description, weaknesses, references |

### Cross-Referencing & Assessment

| Tool | Description |
|------|-------------|
| `search_owasp` | Search across **all 11 local data sources** at once |
| `cross_reference` | Map a `cwe` ID to Top 10 categories, ASVS requirements, and WSTG tests |
| `compliance_map` | Map ASVS chapters to **PCI-DSS 4.0**, **ISO 27001:2022**, and **NIST SP 800-53 Rev. 5** |
| `assess_stack` | Input a tech stack (e.g., "React, Node.js, PostgreSQL") and get tailored security recommendations |
| `generate_checklist` | Generate security testing checklists by project type (web/api/mobile/llm/full) and depth (basic/standard/comprehensive) |
| `assess_mcp_security` | Assess an MCP server deployment against the OWASP MCP Top 10 security risks |
| `threat_model` | Generate a **STRIDE-based threat model** for any system with OWASP mitigations |

### Database Management

| Tool | Description |
|------|-------------|
| `update_database` | Rebuild the local index from upstream OWASP sources |
| `database_status` | Show database availability, build time, size, and path |

## Prompt Templates (4 prompts)

Pre-built security workflows that guide the LLM through structured analysis using OWASP tools:

| Prompt | Description |
|--------|-------------|
| `security_review` | Guided security review — analyzes a system against OWASP Top 10, ASVS, WSTG, and Cheat Sheets |
| `threat_analysis` | Threat analysis workflow — identifies threats, maps to CWEs, and recommends test cases |
| `compliance_check` | Compliance assessment — maps system requirements to ASVS with testing procedures |
| `secure_code_review` | Code-focused security review — identifies vulnerabilities with CWE IDs and secure alternatives |

## Resources (6 URIs)

Structured data endpoints that MCP clients can read for context:

| URI | Description |
|-----|-------------|
| `owasp://about` | Server version, database status, available tools and prompts |
| `owasp://stats` | Database statistics — record counts per source, DB size, build time |
| `owasp://top10/2021` | Full OWASP Top 10 2021 content |
| `owasp://api-top10/2023` | Full API Security Top 10 2023 content |
| `owasp://llm-top10/2025` | Full LLM Top 10 2025 content |
| `owasp://proactive-controls/2024` | Full Proactive Controls 2024 content |

## Usage Examples

```
> List all OWASP flagship projects

> Search OWASP for authentication best practices

> Show ASVS requirements for chapter V7 at level 2

> What WSTG tests cover SQL injection?

> Look up CWE-79 and show me all OWASP references

> Search NVD for critical log4j CVEs

> Map ASVS chapter V4 to PCI-DSS and ISO 27001

> Cross-reference CWE-918 with OWASP standards

> Generate a STRIDE threat model for my e-commerce API

> Assess my MCP server security: it uses shell exec, no auth, community plugins

> What are the MCP Top 10 security risks?

> What are the API Security Top 10 risks?

> Show me the LLM Top 10 for prompt injection

> Assess the security of my stack: React, Node.js, PostgreSQL, REST API

> Generate a comprehensive security checklist for a web API project

> Show me the Input Validation cheat sheet
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `OWASP_MCP_DATA_DIR` | `~/.owasp-mcp` | Local database and cache directory |
| `OWASP_MCP_UPDATE_INTERVAL` | `604800` (7 days) | Auto-refresh interval in seconds |
| `NVD_API_KEY` | _(none)_ | Optional NVD API key for higher rate limits (50 req/30s vs 5 req/30s) |

## Architecture

```
┌─────────────────────────────────┐
│         MCP Client              │
│  (Claude / Cursor / OpenCode)   │
└──────────────┬──────────────────┘
               │ stdio
┌──────────────▼──────────────────┐
│         owasp-mcp server        │
│  24 tools · 4 prompts · 6 rsrc │
├─────────────────────────────────┤
│         SQLite + FTS5           │
│  Full-text search index (~930KB)│
├──────────────┬──────────────────┤
│  Collectors  │  Live APIs       │
│  (11 local)  │  NVD CVE 2.0    │
└──────────────┴──────────────────┘
               │ httpx
┌──────────────▼──────────────────┐
│  OWASP GitHub · MITRE NVD      │
│  Raw JSON/Markdown (public)     │
└─────────────────────────────────┘
```

## Development

```bash
git clone https://github.com/zer0-kr/owasp-mcp.git
cd owasp-mcp
pip install -e ".[dev]"

# Run tests (224 test cases across 38 groups)
python tests/test_comprehensive.py

# Run server locally
python -m owasp_mcp
```

### Project Structure

```
src/owasp_mcp/
├── server.py              # FastMCP entry point + prompts + resources
├── config.py              # Environment-based configuration
├── db.py                  # SQLite FTS5 query helpers
├── index.py               # IndexManager — builds DB from collectors
├── nvd.py                 # NVD API client (live CVE search)
├── collectors/
│   ├── projects.py        # 418+ project metadata
│   ├── asvs.py            # ASVS 5.0 flat JSON
│   ├── wstg.py            # WSTG checklist JSON
│   ├── top10.py           # Top 10 2021 + CWE mappings
│   ├── api_top10.py       # API Security Top 10 2023
│   ├── llm_top10.py       # LLM Top 10 2025
│   ├── mcp_top10.py       # MCP Top 10 2025
│   ├── proactive_controls.py  # Proactive Controls 2024
│   ├── masvs.py           # MASVS mobile security
│   ├── cwe_data.py        # CWE database (38 entries)
│   └── cheatsheets.py     # Cheat Sheet index + on-demand content
└── tools/
    └── owasp_tools.py     # All 24 MCP tool definitions
```

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feat/my-feature`)
3. Run the test suite (`python tests/test_comprehensive.py`)
4. Commit your changes
5. Open a Pull Request

## Disclaimer

This project is not officially affiliated with or endorsed by the OWASP Foundation. All data is sourced from publicly available OWASP GitHub repositories under their respective licenses.

## License

[MIT](LICENSE)
