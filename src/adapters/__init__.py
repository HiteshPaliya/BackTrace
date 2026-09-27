"""Pluggable tool adapters for external static security tools."""

from src.adapters.base import ToolAdapter, ToolExecutionResult
from src.adapters.manager import ToolManager
from src.adapters.noir import NoirAdapter
from src.adapters.semgrep import SemgrepAdapter
from src.adapters.trufflehog import TruffleHogAdapter

__all__ = [
    "ToolAdapter",
    "ToolExecutionResult",
    "ToolManager",
    "NoirAdapter",
    "SemgrepAdapter",
    "TruffleHogAdapter",
]
