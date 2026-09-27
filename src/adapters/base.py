"""Abstract base classes and execution results for external tool adapters."""

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolExecutionResult:
    """Standardized result envelope for external tool execution."""

    tool_name: str
    is_available: bool
    exit_code: int
    raw_output: str
    parsed_items: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ToolAdapter(ABC):
    """Abstract adapter interface wrapping third-party CLI static analyzers."""

    TIMEOUT_SECONDS: int = 180

    @property
    @abstractmethod
    def name(self) -> str:
        """Name identifier of the tool."""
        pass

    def is_installed(self) -> bool:
        """Check if tool binary is resolvable on system PATH."""
        return shutil.which(self.name) is not None

    def execute_command(
        self,
        cmd: List[str],
        cwd: Path,
        timeout: Optional[int] = None,
    ) -> ToolExecutionResult:
        """Execute tool command in subprocess with strict timeout and envelope handling."""
        effective_timeout = timeout or self.TIMEOUT_SECONDS
        if not self.is_installed():
            return ToolExecutionResult(
                tool_name=self.name,
                is_available=False,
                exit_code=-1,
                raw_output="",
                warnings=[f"Tool binary '{self.name}' not found on PATH. Softly degraded."],
            )

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
            )
            raw = proc.stdout
            parsed = self.normalize(raw)
            return ToolExecutionResult(
                tool_name=self.name,
                is_available=True,
                exit_code=proc.returncode,
                raw_output=raw,
                parsed_items=parsed,
            )
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                tool_name=self.name,
                is_available=True,
                exit_code=-1,
                raw_output="",
                warnings=[f"Execution of '{self.name}' timed out after {effective_timeout}s."],
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name=self.name,
                is_available=True,
                exit_code=-1,
                raw_output="",
                warnings=[f"Execution of '{self.name}' failed: {exc}"],
            )

    @abstractmethod
    def run(self, repo_path: Path, options: Optional[Dict[str, Any]] = None) -> ToolExecutionResult:
        """Execute scan against given repository path."""
        pass

    @abstractmethod
    def normalize(self, raw_output: str) -> List[Dict[str, Any]]:
        """Normalize raw scanner output into canonical structured dictionary records."""
        pass
