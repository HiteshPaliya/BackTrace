"""OASIS SARIF 2.1.0 standard exporter for vulnerability dossiers."""

import json
from typing import Any, Dict, List


class SARIFExporter:
    """Exports vulnerability findings to standard OASIS SARIF 2.1.0 schema."""

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def export(self, dossiers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert list of dossier records to SARIF v2.1.0 dictionary."""
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        rule_ids_seen = set()

        for d in dossiers:
            rule_id = d.get("cwe_id") or d.get("vuln_class", "SEC-VULN")
            sev_level = "error" if d.get("severity") in ("CRITICAL", "HIGH") else "warning"
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "name": d.get("vuln_class", "SecurityVulnerability"),
                        "shortDescription": {"text": d.get("title", "")},
                        "defaultConfiguration": {"level": sev_level},
                    }
                )

            # Extract location from source trace if present
            raw_trace = d.get("source_trace_json") or d.get("source_trace") or "[]"
            trace = json.loads(raw_trace) if isinstance(raw_trace, str) else raw_trace
            first_loc = trace[0] if isinstance(trace, list) and trace else {}

            file_path = first_loc.get("file", "unknown")
            line_no = first_loc.get("line", 1)
            msg_text = f"{d.get('title')}: {d.get('verdict')} (confidence: {d.get('confidence')})"

            results.append(
                {
                    "ruleId": rule_id,
                    "level": sev_level,
                    "message": {"text": msg_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path},
                                "region": {"startLine": int(line_no)},
                            }
                        }
                    ],
                }
            )

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PolyglotSourceCodeSecurityReviewer",
                            "semanticVersion": "0.1.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
