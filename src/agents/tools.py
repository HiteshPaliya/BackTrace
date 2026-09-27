"""Tooling utilities provided to Strands LLM agents."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.storage.db import DatabaseManager


class AgentTools:
    """Agent toolbelt for querying codebase and symbol index."""

    @staticmethod
    def grep_codebase(root_path: Path | str, pattern: str) -> List[Dict[str, Any]]:
        """Grep codebase for regex pattern across non-ignored files."""
        root = Path(root_path).resolve()
        compiled = re.compile(pattern)
        matches: List[Dict[str, Any]] = []

        for p in root.rglob("*"):
            if not p.is_file() or any(
                part in {".git", ".audit", ".superpowers", "node_modules", ".venv"}
                for part in p.parts
            ):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                for idx, line in enumerate(content.splitlines(), start=1):
                    if compiled.search(line):
                        matches.append(
                            {
                                "file": str(p.relative_to(root)),
                                "line": idx,
                                "text": line.strip(),
                            }
                        )
            except OSError:
                continue

        return matches[:50]  # Limit to 50 matches

    @staticmethod
    def lookup_symbol(db: DatabaseManager, name: str) -> Optional[Dict[str, Any]]:
        """Look up symbol in SQLite repository graph."""
        return db.get_symbol_by_name(name)

    @staticmethod
    def read_file_lines(
        file_path: Path | str,
        start_line: int,
        end_line: int,
    ) -> str:
        """Read specific line range from file."""
        p = Path(file_path).resolve()
        if not p.is_file():
            return ""
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            selected = lines[max(0, start_line - 1) : end_line]
            return "\n".join(selected)
        except OSError:
            return ""
