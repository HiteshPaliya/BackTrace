"""Tests for WorkspaceManager and FileInfo."""

from pathlib import Path

import pytest

from src.core.workspace import WorkspaceManager


def test_workspace_canonicalization_and_filtering(tmp_path: Path):
    """Happy path: Discover source files, tag vendor files, and filter minified files."""
    src_file = tmp_path / "app.py"
    src_file.write_text("print('hello world')\n", encoding="utf-8")

    vendor_dir = tmp_path / "node_modules" / "pkg"
    vendor_dir.mkdir(parents=True)
    vendor_file = vendor_dir / "index.js"
    vendor_file.write_text("module.exports = {}\n", encoding="utf-8")

    min_file = tmp_path / "bundle.min.js"
    min_file.write_text("a" * 2000, encoding="utf-8")

    wm = WorkspaceManager(root_path=tmp_path)
    files = wm.discover_files()

    rel_paths = {f.rel_path.replace("\\", "/") for f in files}
    assert "app.py" in rel_paths
    assert "bundle.min.js" not in rel_paths  # Minified files skipped

    vendor_f = next(
        f for f in files if f.rel_path.replace("\\", "/") == "node_modules/pkg/index.js"
    )
    assert vendor_f.is_vendor is True
    assert vendor_f.language == "javascript"

    py_f = next(f for f in files if f.rel_path.replace("\\", "/") == "app.py")
    assert py_f.is_vendor is False
    assert py_f.language == "python"
    assert py_f.loc == 1
    assert len(py_f.file_hash) == 64  # SHA256 hex string


def test_workspace_file_size_cutoff_2mb(tmp_path: Path):
    """Boundary test: Files exceeding 2MB circuit breaker are skipped."""
    large_file = tmp_path / "large_payload.py"
    # 2MB + 1 byte
    large_file.write_bytes(b"x" * (2 * 1024 * 1024 + 1))

    wm = WorkspaceManager(root_path=tmp_path)
    files = wm.discover_files()
    rel_paths = {f.rel_path.replace("\\", "/") for f in files}
    assert "large_payload.py" not in rel_paths


def test_workspace_binary_files_filtered(tmp_path: Path):
    """Boundary test: Raw binary files with null bytes are skipped safely."""
    bin_file = tmp_path / "binary_blob.dat"
    bin_file.write_bytes(b"\x00\x01\x02\x03\x04\xff")

    wm = WorkspaceManager(root_path=tmp_path)
    files = wm.discover_files()
    rel_paths = {f.rel_path.replace("\\", "/") for f in files}
    assert "binary_blob.dat" not in rel_paths


def test_workspace_path_canonicalization_security(tmp_path: Path):
    """Security test: Prevent directory traversal outside root."""
    wm = WorkspaceManager(root_path=tmp_path)
    # Outside path should raise ValueError or return None
    with pytest.raises(ValueError):
        wm.canonicalize_path(tmp_path.parent / "secret.txt")


def test_workspace_language_detection(tmp_path: Path):
    """Happy path: Polyglot language detection."""
    wm = WorkspaceManager(root_path=tmp_path)
    assert wm.detect_language("test.py") == "python"
    assert wm.detect_language("index.js") == "javascript"
    assert wm.detect_language("app.ts") == "typescript"
    assert wm.detect_language("main.go") == "go"
    assert wm.detect_language("App.java") == "java"
    assert wm.detect_language("script.rb") == "ruby"
    assert wm.detect_language("index.php") == "php"
    assert wm.detect_language("unknown.xyz") is None
