from __future__ import annotations

import os
from pathlib import Path


class Config:
    def __init__(self) -> None:
        self.data_dir = Path(
            os.environ.get("OWASP_MCP_DATA_DIR", Path.home() / ".owasp-mcp")
        )
        self.update_interval = int(
            os.environ.get("OWASP_MCP_UPDATE_INTERVAL", 7 * 86400)
        )
        self.data_dir.mkdir(parents=True, exist_ok=True)


def get_config() -> Config:
    return Config()
