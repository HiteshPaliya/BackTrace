"""OWASP Noir adapter for attack surface and endpoint discovery."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.base import ToolAdapter, ToolExecutionResult


class NoirAdapter(ToolAdapter):
    """Adapter wrapping OWASP Noir attack surface mapping CLI."""

    @property
    def name(self) -> str:
        return "noir"

    def run(self, repo_path: Path, options: Optional[Dict[str, Any]] = None) -> ToolExecutionResult:
        cmd = ["noir", "-b", str(repo_path), "--format", "json"]
        return self.execute_command(cmd, cwd=repo_path)

    def normalize(self, raw_output: str) -> List[Dict[str, Any]]:
        """Normalize Noir JSON into canonical endpoint dictionaries."""
        if not raw_output or not raw_output.strip():
            return []

        try:
            data = json.loads(raw_output)
        except Exception:
            return []

        endpoints: List[Dict[str, Any]] = []
        raw_list = data.get("endpoints", []) if isinstance(data, dict) else []

        for item in raw_list:
            details = item.get("details", {})
            endpoints.append(
                {
                    "http_method": item.get("method", "GET").upper(),
                    "route_pattern": item.get("url", ""),
                    "rel_path": details.get("file", ""),
                    "line_number": int(details.get("line", 1)),
                    "auth_required": bool(item.get("auth_required", False)),
                    "parameters": item.get("params", []),
                    "tool_provenance": "Noir",
                }
            )

        return endpoints
