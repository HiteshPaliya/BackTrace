"""Semantic intermediate transform and sanitizer models."""

from dataclasses import dataclass


@dataclass
class SemanticTransform:
    """An intermediate data transform, sanitizer, path constructor, or validation guard."""

    expression: str
    category: str
    line_number: int
    file_path: str
