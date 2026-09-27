"""Tool manager orchestrating execution across all registered static analyzers."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.base import ToolAdapter, ToolExecutionResult
from src.adapters.noir import NoirAdapter
from src.adapters.semgrep import SemgrepAdapter
from src.adapters.trufflehog import TruffleHogAdapter


class ToolManager:
    """Coordinates and orchestrates execution of multiple pluggable tool adapters."""

    def __init__(self, adapters: Optional[List[ToolAdapter]] = None) -> None:
        self.adapters = adapters if adapters is not None else [
            NoirAdapter(),
            SemgrepAdapter(),
            TruffleHogAdapter(),
        ]

    def run_all(
        self,
        repo_path: Path,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, ToolExecutionResult]:
        """Run all configured adapters with soft degradation when tools fail or are missing."""
        results: Dict[str, ToolExecutionResult] = {}
        for adapter in self.adapters:
            try:
                results[adapter.name] = adapter.run(repo_path, options=options)
            except Exception as exc:
                results[adapter.name] = ToolExecutionResult(
                    tool_name=adapter.name,
                    is_available=False,
                    exit_code=-1,
                    raw_output="",
                    warnings=[f"Failed to execute adapter '{adapter.name}': {exc}"],
                )
        return results
