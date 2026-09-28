"""Semantic untrusted source data models."""

from dataclasses import dataclass


@dataclass
class SemanticSource:
    """An identified source of untrusted user-controlled input."""

    expression: str
    source_type: str
    line_number: int
    file_path: str
