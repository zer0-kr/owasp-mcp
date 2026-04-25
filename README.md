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

Search and query **418+ OWASP projects** across all maturity levels, **345 ASVS requirements**, **111 WSTG test cases**, **113+ Cheat Sheets**, and the **Top 10 2021** with CWE cross-references — all through a single MCP interface.

## Why owasp-mcp?

Individual OWASP resources are scattered across dozens of repositories with different formats. This server unifies them into one searchable interface:

- Ask "What are the ASVS requirements for authentication?" and get structured results instantly
- Cross-reference a CWE with Top 10 categories, ASVS requirements, and WSTG test cases
- Browse all 418+ OWASP projects including Lab and Incubator — not just the Flagship ones
- Pull full Cheat Sheet content on demand without leaving your workflow

No API keys required. All data is fetched from public OWASP GitHub repositories.

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
| **Cheat Sheets** | 113+ | [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) |

Project levels: **Flagship** (15) · **Production** (12+) · **Lab** (36) · **Incubator** (206+) · Retired

## Tools Reference

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
| `get_top10` | Get Top 10 2021 items with descriptions and CWE mappings. Pass `id` (e.g., A03:2021) or omit to list all |
| `get_cheatsheet` | Read a cheat sheet by `name` or list all 113+ available sheets |

### Cross-Referencing

| Tool | Description |
|------|-------------|
| `search_owasp` | Search across **all** data sources at once (projects + ASVS + WSTG + Top 10 + Cheat Sheets) |
| `cross_reference` | Map a `cwe` ID (e.g., CWE-79) to Top 10 categories, ASVS requirements, and WSTG tests. Or pass `top10_id` to see all associated CWEs |

### Database Management

| Tool | Description |
|------|-------------|
| `update_database` | Rebuild the local index from upstream OWASP sources |
| `database_status` | Show database availability, build time, size, and path |

## Usage Examples

```
> List all OWASP flagship projects

> Search OWASP for authentication best practices

> Show ASVS requirements for chapter V7 at level 2

> What WSTG tests cover SQL injection?

> Cross-reference CWE-79 with OWASP standards

> Get the OWASP Top 10 item for A03:2021

> Show me the Input Validation cheat sheet

> Search all OWASP data for "session management"
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `OWASP_MCP_DATA_DIR` | `~/.owasp-mcp` | Local database and cache directory |
| `OWASP_MCP_UPDATE_INTERVAL` | `604800` (7 days) | Auto-refresh interval in seconds |

## Architecture

```
┌─────────────────────────────────┐
│         MCP Client              │
│  (Claude / Cursor / OpenCode)   │
└──────────────┬──────────────────┘
               │ stdio
┌──────────────▼──────────────────┐
│         owasp-mcp server        │
│  FastMCP · 11 tools · 1 resource│
├─────────────────────────────────┤
│         SQLite + FTS5           │
│  Full-text search index (~675KB)│
├─────────────────────────────────┤
│         Collectors              │
│  projects · asvs · wstg · top10 │
│  cheatsheets                    │
└──────────────┬──────────────────┘
               │ httpx (on build)
┌──────────────▼──────────────────┐
│     OWASP GitHub Repos          │
│  Raw JSON/Markdown (public)     │
└─────────────────────────────────┘
```

## Development

```bash
git clone https://github.com/zer0-kr/owasp-mcp.git
cd owasp-mcp
pip install -e ".[dev]"

# Run tests (91 test cases)
python tests/test_comprehensive.py

# Run server locally
python -m owasp_mcp
```

### Project Structure

```
src/owasp_mcp/
├── server.py              # FastMCP entry point
├── config.py              # Environment-based configuration
├── db.py                  # SQLite FTS5 query helpers
├── index.py               # IndexManager — builds DB from collectors
├── collectors/
│   ├── projects.py        # 418+ project metadata
│   ├── asvs.py            # ASVS 5.0 flat JSON
│   ├── wstg.py            # WSTG checklist JSON
│   ├── top10.py           # Top 10 2021 + CWE mappings
│   └── cheatsheets.py     # Cheat Sheet index + on-demand content
└── tools/
    └── owasp_tools.py     # All MCP tool definitions
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
