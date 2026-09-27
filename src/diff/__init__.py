"""Incremental Git-diff analysis, working tree evaluation, and version gating."""

from src.diff.git_scanner import DiffImpactPlan, GitDiffEngine

__all__ = ["DiffImpactPlan", "GitDiffEngine"]
