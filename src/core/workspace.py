"""Workspace manager for path canonicalization, filtering, and file discovery."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class FileInfo:
    """Metadata representing a canonicalized discovered file."""

    rel_path: str
    abs_path: str
    language: Optional[str]
    is_vendor: bool
    file_hash: str
    loc: int


class WorkspaceManager:
    """Discovers, validates, and canonicalizes project files for security scanning."""

    MAX_FILE_SIZE: int = 2 * 1024 * 1024  # 2MB
    MAX_AVG_LINE_LENGTH: int = 1000

    VENDOR_PARTS = {"node_modules", "vendor", "site-packages", ".venv", "venv"}
    IGNORED_DIRS = {".git", ".audit", ".superpowers", ".pytest_cache", "__pycache__"}

    LANGUAGE_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
    }

    def __init__(self, root_path: Path | str) -> None:
        self.root_path = Path(root_path).resolve()

    def canonicalize_path(self, target_path: Path | str) -> Path:
        """Resolve target path securely, preventing directory traversal outside root."""
        resolved = Path(target_path).resolve()
        try:
            resolved.relative_to(self.root_path)
        except ValueError as exc:
            raise ValueError(
                f"Path traversal detected: {target_path} is outside root {self.root_path}"
            ) from exc
        return resolved

    def detect_language(self, path: Path | str) -> Optional[str]:
        """Detect language by file extension."""
        suffix = Path(path).suffix.lower()
        return self.LANGUAGE_MAP.get(suffix)

    def is_vendor_path(self, rel_path: Path) -> bool:
        """Check if relative path touches known vendor directories."""
        return any(part in self.VENDOR_PARTS for part in rel_path.parts)

    def discover_files(self) -> List[FileInfo]:
        """Walk the workspace and return validated, non-minified, non-binary source files."""
        discovered: List[FileInfo] = []

        for path in self.root_path.rglob("*"):
            if not path.is_file():
                continue

            rel_path = path.relative_to(self.root_path)
            # Skip ignored directories
            if any(part in self.IGNORED_DIRS for part in rel_path.parts):
                continue

            # Circuit breaker: file size <= 2MB
            file_size = path.stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                continue

            try:
                raw_bytes = path.read_bytes()
            except OSError:
                continue

            # Filter binary files
            if b"\x00" in raw_bytes[:1024]:
                continue

            try:
                content = raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue

            lines = content.splitlines()
            total_lines = len(lines)
            if total_lines > 0:
                avg_line_length = len(content) / total_lines
                if avg_line_length > self.MAX_AVG_LINE_LENGTH:
                    # Skip minified files
                    continue

            file_hash = hashlib.sha256(raw_bytes).hexdigest()
            language = self.detect_language(path)
            is_vendor = self.is_vendor_path(rel_path)

            discovered.append(
                FileInfo(
                    rel_path=str(rel_path),
                    abs_path=str(path.resolve()),
                    language=language,
                    is_vendor=is_vendor,
                    file_hash=file_hash,
                    loc=total_lines,
                )
            )

        return discovered


class SourceHydrator:
    """Hydrates source code snippets directly from filesystem when external tools redact them."""

    def __init__(self, root_path: Path | str) -> None:
        self.root_path = Path(root_path).resolve()

    def hydrate_snippet(
        self,
        rel_path: str,
        line_number: int,
        tool_snippet: str,
        context_lines: int = 0,
    ) -> str:
        """Resolve actual source line from disk if tool snippet is missing or 'requires login'."""
        if tool_snippet and tool_snippet.strip().lower() != "requires login":
            return tool_snippet

        target_file = (self.root_path / rel_path).resolve()
        if not target_file.is_file():
            return tool_snippet

        try:
            lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if 1 <= line_number <= len(lines):
                start = max(0, line_number - 1 - context_lines)
                end = min(len(lines), line_number + context_lines)
                return "\n".join(lines[start:end]).strip()
        except OSError:
            pass

        return tool_snippet
