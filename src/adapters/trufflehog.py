"""TruffleHog adapter for hardcoded secrets and credentials scanning."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.base import ToolAdapter, ToolExecutionResult


class TruffleHogAdapter(ToolAdapter):
    """Adapter wrapping TruffleHog filesystem secret scanner."""

    @property
    def name(self) -> str:
        return "trufflehog"

    def run(self, repo_path: Path, options: Optional[Dict[str, Any]] = None) -> ToolExecutionResult:
        cmd = ["trufflehog", "filesystem", str(repo_path), "--json"]
        return self.execute_command(cmd, cwd=repo_path)

    def normalize(self, raw_output: str) -> List[Dict[str, Any]]:
        """Normalize TruffleHog newline-delimited JSON into canonical secret dictionaries."""
        if not raw_output or not raw_output.strip():
            return []

        secrets: List[Dict[str, Any]] = []
        for line in raw_output.strip().splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
            except Exception:
                continue

            src_meta = record.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            file_path = src_meta.get("file", record.get("file", ""))
            detector = record.get("DetectorName", "GenericSecret")
            verified = bool(record.get("Verified", False))
            raw_secret = record.get("Raw", "")
            line_num = int(record.get("line", 1))

            secrets.append(
                {
                    "rel_path": file_path,
                    "detector_name": detector,
                    "verified": verified,
                    "raw_secret": raw_secret,
                    "line_number": line_num,
                    "tool_provenance": "TruffleHog",
                }
            )

        return secrets
