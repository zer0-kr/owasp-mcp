# owasp-mcp

MCP server for unified access to all OWASP projects, standards, and security guidelines.

Covers **418+ projects** across all maturity levels (Flagship, Production, Lab, Incubator) plus ASVS 5.0, WSTG, Top 10 2021, and 113+ Cheat Sheets — all searchable through a single interface.

## Data Sources

| Source | Records | Description |
|--------|---------|-------------|
| Projects | 418+ | Full OWASP project catalog with metadata |
| ASVS 5.0 | 345 | Application Security Verification Standard |
| WSTG | 111 | Web Security Testing Guide test cases |
| Top 10 2021 | 10 | Top 10 risks with CWE mappings |
| Cheat Sheets | 113+ | Security cheat sheets (on-demand content) |

## Tools

| Tool | Description |
|------|-------------|
| `list_projects` | Browse all projects with level/type filters |
| `search_projects` | Full-text search across projects |
| `get_project` | Get detailed project info |
| `search_owasp` | Cross-source search (all data at once) |
| `get_top10` | Top 10 2021 items with CWE mappings |
| `get_asvs` | ASVS 5.0 requirements (filter by chapter/level) |
| `get_wstg` | WSTG test cases (filter by category) |
| `get_cheatsheet` | List or read cheat sheets |
| `cross_reference` | CWE <-> Top 10 <-> ASVS mapping |
| `update_database` | Rebuild local index from OWASP sources |
| `database_status` | Show local database info |

## Installation

```bash
pip install git+https://github.com/zer0-kr/owasp-mcp.git
```

Or clone and install locally:

```bash
git clone https://github.com/zer0-kr/owasp-mcp.git
cd owasp-mcp
pip install -e .
```

## Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "owasp": {
      "command": "owasp-mcp"
    }
  }
}
```

The database is built automatically on first use (~5-10 seconds) and cached locally at `~/.owasp-mcp/`. It refreshes weekly by default.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OWASP_MCP_DATA_DIR` | `~/.owasp-mcp` | Local database directory |
| `OWASP_MCP_UPDATE_INTERVAL` | `604800` (7 days) | Staleness threshold in seconds |

## Usage Examples

Once connected via Claude Desktop or any MCP client:

- "List all OWASP flagship projects"
- "Search OWASP for authentication best practices"
- "Show me the ASVS requirements for session management"
- "What WSTG tests cover SQL injection?"
- "Get the OWASP Top 10 item for A03:2021"
- "Cross-reference CWE-79 with OWASP standards"
- "Show me the SQL Injection Prevention cheat sheet"

## Architecture

- **Runtime:** Python 3.11+, FastMCP, httpx
- **Storage:** SQLite with FTS5 full-text search
- **Transport:** stdio (for Claude Desktop / MCP clients)
- **Data:** Fetched from OWASP GitHub repositories (no API keys needed)

## License

MIT
