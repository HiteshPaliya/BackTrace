"""Semantic candidate sink models with contextual metadata."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SemanticSink:
    """An identified candidate operation that may trigger vulnerability if tainted."""

    vuln_class: str
    expression: str
    triage_severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    line_number: int
    file_path: str
    cwe_id: Optional[str] = None
    sink_context: Optional[str] = None
    argument_expression: Optional[str] = None
    is_variable_argument: bool = True
    sink_api: Optional[str] = None
    scope: str = "APPLICATION_RUNTIME"
