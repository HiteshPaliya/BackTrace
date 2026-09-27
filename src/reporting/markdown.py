"""Markdown research report exporter for security findings and reproduction blueprints."""

import json
from typing import Any, Dict, List, Optional


class MarkdownExporter:
    """Exports vulnerability dossiers into human-readable, research-grade Markdown reports."""

    def export(self, dossiers: List[Dict[str, Any]], scan_id: Optional[str] = None) -> str:
        """Render findings and reproduction blueprints to Markdown."""
        lines = [
            "# Security Review Research Dossier",
            f"**Scan ID:** `{scan_id or 'N/A'}`",
            f"**Total Findings:** {len(dossiers)}",
            "",
            "## Executive Summary",
            "",
            "| Finding ID | Title | Vuln Class | Severity | Verdict | Confidence |",
            "|---|---|---|---|---|---|",
        ]

        for d in dossiers:
            lines.append(
                f"| `{d.get('dossier_id')}` | {d.get('title')} | `{d.get('vuln_class')}` | "
                f"**{d.get('severity')}** | `{d.get('verdict')}` | {d.get('confidence')} |"
            )

        lines.extend(["", "---", "", "## Detailed Vulnerability Theories & Reproductions", ""])

        for idx, d in enumerate(dossiers, start=1):
            lines.extend(
                [
                    f"### {idx}. {d.get('title')}",
                    f"- **Vulnerability Class:** `{d.get('vuln_class')}` ({d.get('cwe_id')})",
                    f"- **Severity:** `{d.get('severity')}`",
                    f"- **Taint Verdict:** `{d.get('verdict')}`",
                    f"- **Confidence:** {d.get('confidence')}",
                    "",
                    "#### Sanitizer & Bypass Analysis",
                ]
            )

            raw_analysis = d.get("sanitizer_analysis_json") or d.get("sanitizer_analysis") or "{}"
            analysis = json.loads(raw_analysis) if isinstance(raw_analysis, str) else raw_analysis

            if analysis:
                for k, v in analysis.items():
                    if v:
                        header = k.replace("_", " ").title()
                        lines.append(f"**{header}:** {v}\n")

            if d.get("repro_curl_template"):
                lines.extend(
                    [
                        "#### Reproduction Blueprint (curl)",
                        "```bash",
                        d.get("repro_curl_template", "").strip(),
                        "```",
                        "",
                    ]
                )

            if d.get("mitigation_notes"):
                lines.extend(
                    [
                        "#### Mitigation & Remediation",
                        d.get("mitigation_notes", "").strip(),
                        "",
                    ]
                )

            lines.append("---")

        return "\n".join(lines)
