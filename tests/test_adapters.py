"""Tests for pluggable ToolAdapter framework (Noir, Semgrep, TruffleHog)."""

import subprocess
from pathlib import Path
from unittest.mock import patch

from src.adapters.base import ToolAdapter, ToolExecutionResult
from src.adapters.manager import ToolManager
from src.adapters.noir import NoirAdapter
from src.adapters.semgrep import SemgrepAdapter
from src.adapters.trufflehog import TruffleHogAdapter


class MockMissingTool(ToolAdapter):
    @property
    def name(self) -> str:
        return "missing_tool"

    def is_installed(self) -> bool:
        return False

    def run(self, repo_path: Path, options: dict = None) -> ToolExecutionResult:
        raise FileNotFoundError("Binary not found")

    def normalize(self, raw_output: str) -> list:
        return []


def test_tool_manager_handles_missing_tool_softly(tmp_path: Path):
    """Boundary test: Missing tool gracefully reports unavailable with warnings."""
    manager = ToolManager(adapters=[MockMissingTool()])
    results = manager.run_all(tmp_path)

    assert "missing_tool" in results
    assert results["missing_tool"].is_available is False
    assert len(results["missing_tool"].warnings) > 0


def test_noir_adapter_normalization():
    """Happy path: Noir output parses endpoints correctly."""
    adapter = NoirAdapter()
    sample_json = """
    {
      "endpoints": [
        {
          "method": "POST",
          "url": "/api/v1/user",
          "details": {
            "file": "app.py",
            "line": 42
          },
          "params": [{"name": "username", "in": "body"}]
        }
      ]
    }
    """
    endpoints = adapter.normalize(sample_json)
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep["http_method"] == "POST"
    assert ep["route_pattern"] == "/api/v1/user"
    assert ep["rel_path"] == "app.py"
    assert ep["line_number"] == 42


def test_semgrep_adapter_normalization():
    """Happy path: Semgrep output parses candidate sinks correctly."""
    adapter = SemgrepAdapter()
    sample_json = """
    {
      "results": [
        {
          "check_id": "rules.python.security.rce.os-system",
          "path": "server.py",
          "start": {"line": 15, "col": 5},
          "extra": {
            "message": "Found dangerous command execution",
            "metadata": {"cwe": "CWE-78", "category": "security"},
            "severity": "ERROR",
            "lines": "os.system(user_input)"
          }
        }
      ]
    }
    """
    sinks = adapter.normalize(sample_json)
    assert len(sinks) == 1
    sink = sinks[0]
    assert sink["rel_path"] == "server.py"
    assert sink["vuln_class"] == "RCE"
    assert sink["severity"] == "CRITICAL"
    assert sink["line_number"] == 15
    assert sink["sink_expression"] == "os.system(user_input)"


def test_trufflehog_adapter_normalization():
    """Happy path: TruffleHog json lines parse secrets correctly."""
    adapter = TruffleHogAdapter()
    sample_lines = (
        '{"SourceMetadata":{"Data":{"Filesystem":{"file":"config.py"}}},'
        '"DetectorName":"AWS","SourceID":1,"Raw":"AKIAIOSFODNN7EXAMPLE",'
        '"Verified":true,"line":12}\n'
    )
    secrets = adapter.normalize(sample_lines)
    assert len(secrets) == 1
    sec = secrets[0]
    assert sec["rel_path"] == "config.py"
    assert sec["detector_name"] == "AWS"
    assert sec["verified"] is True
    assert sec["line_number"] == 12


def test_adapter_timeout_handling(tmp_path: Path):
    """Error boundary: Subprocess timeout produces soft failure with warning."""
    adapter = NoirAdapter()
    with patch("shutil.which", return_value="/usr/bin/noir"):
        timeout_err = subprocess.TimeoutExpired(cmd="noir", timeout=180)
        with patch("subprocess.run", side_effect=timeout_err):
            res = adapter.run(tmp_path)
            assert res.is_available is True
            assert res.exit_code == -1
            assert any("timed out" in w.lower() for w in res.warnings)
