"""Semgrep adapter for candidate vulnerability sink discovery."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.base import ToolAdapter, ToolExecutionResult


class SemgrepAdapter(ToolAdapter):
    """Adapter wrapping Semgrep SAST engine for candidate sink identification."""

    @property
    def name(self) -> str:
        return "semgrep"

    def run(self, repo_path: Path, options: Optional[Dict[str, Any]] = None) -> ToolExecutionResult:
        cmd = ["semgrep", "scan", "--json", "--quiet"]
        return self.execute_command(cmd, cwd=repo_path)

    def _infer_vuln_class(self, rule_id: str, message: str) -> str:
        haystack = f"{rule_id} {message}".lower()
        if any(k in haystack for k in ["rce", "command", "exec", "system"]):
            return "RCE"
        if any(k in haystack for k in ["sqli", "sql-injection", "sqlite"]):
            return "SQLI"
        if "ssrf" in haystack:
            return "SSRF"
        if any(k in haystack for k in ["traversal", "path", "zip-slip"]):
            return "PATH_TRAVERSAL"
        if "xss" in haystack:
            return "XSS"
        return "GENERAL_VULN"

    def _map_severity(self, semgrep_severity: str) -> str:
        sev = (semgrep_severity or "INFO").upper()
        if sev == "ERROR":
            return "CRITICAL"
        if sev == "WARNING":
            return "HIGH"
        if sev == "INFO":
            return "MEDIUM"
        return "LOW"

    def normalize(self, raw_output: str) -> List[Dict[str, Any]]:
        """Normalize Semgrep JSON into canonical candidate sink dictionaries."""
        if not raw_output or not raw_output.strip():
            return []

        try:
            data = json.loads(raw_output)
        except Exception:
            return []

        results = data.get("results", []) if isinstance(data, dict) else []
        sinks: List[Dict[str, Any]] = []

        for item in results:
            check_id = item.get("check_id", "unknown.rule")
            extra = item.get("extra", {})
            message = extra.get("message", "")
            raw_lines = extra.get("lines", "").strip()
            cwe = extra.get("metadata", {}).get("cwe")
            cwe_str = cwe[0] if isinstance(cwe, list) and cwe else str(cwe or "")

            vuln_class = self._infer_vuln_class(check_id, message)
            severity = self._map_severity(extra.get("severity", "ERROR"))
            start_line = item.get("start", {}).get("line", 1)

            sinks.append(
                {
                    "rel_path": item.get("path", ""),
                    "vuln_class": vuln_class,
                    "severity": severity,
                    "line_number": int(start_line),
                    "cwe_id": cwe_str or None,
                    "sink_expression": raw_lines or message,
                    "raw_rule_id": check_id,
                    "tool_provenance": "Semgrep",
                }
            )

        return sinks
