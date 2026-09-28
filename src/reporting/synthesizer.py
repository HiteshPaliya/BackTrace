"""Dossier synthesizer compiling verified taint paths into research dossiers."""

import json
import uuid
from typing import Any, Dict, List, Optional

from src.storage.db import VerdictStatus


class DossierSynthesizer:
    """Synthesizes agent verdicts and call sequences into persisted vulnerability dossiers."""

    def synthesize(
        self,
        scan_id: str,
        path_id: Optional[str],
        engine_fingerprint: str,
        title: str,
        vuln_class: str,
        severity: str,
        cwe_id: str,
        verdict: VerdictStatus,
        confidence: float,
        source_trace: List[Dict[str, Any]] | Dict[str, Any],
        sanitizer_analysis: Dict[str, Any],
        repro_curl: Optional[str] = None,
        mitigation: Optional[str] = None,
        dossier_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compile parameters into canonical dossier dictionary."""
        d_id = dossier_id or f"dos_{uuid.uuid4().hex[:12]}"
        verdict_str = verdict.value if isinstance(verdict, VerdictStatus) else str(verdict)

        return {
            "dossier_id": d_id,
            "scan_id": scan_id,
            "path_id": path_id,
            "engine_fingerprint": engine_fingerprint,
            "title": title,
            "vuln_class": vuln_class,
            "severity": severity.upper(),
            "cwe_id": cwe_id,
            "verdict": verdict_str,
            "confidence": confidence,
            "source_trace": source_trace,
            "sanitizer_analysis": sanitizer_analysis,
            "repro_curl_template": repro_curl,
            "mitigation_notes": mitigation,
        }

    def generate_reproduction_template(
        self,
        endpoint_method: Optional[str],
        route_pattern: Optional[str],
        auth_state: str = "NOT_REQUIRED",
        tainted_param: Optional[Dict[str, Any]] = None,
        sibling_params: Optional[List[Dict[str, Any]]] = None,
        sink_target: str = "",
    ) -> Dict[str, Any]:
        """Generate structured non-weaponized reproduction blueprint with inert markers."""
        if not endpoint_method or not route_pattern:
            param_name = tainted_param.get("name", "arg") if tainted_param else "arg"
            return {
                "reproduction_type": "NON_HTTP_TEMPLATE",
                "method": None,
                "route": None,
                "auth_context": {"auth_state": auth_state},
                "parameters": [tainted_param] if tainted_param else [],
                "expected_assertion": {
                    "assertion_type": "CLI_PARAMETER_REACHABILITY",
                    "description": (
                        f"CLI / message parameter '{param_name}' reaches sink {sink_target}"
                    ),
                },
                "curl_command": None,
            }

        method = endpoint_method.upper()
        route = route_pattern
        auth_header = (
            ' -H "Authorization: Bearer ${AUTH_TOKEN}"'
            if auth_state == "REQUIRED"
            else ""
        )
        inert_marker = "BT_FLOW_MARKER_001"

        param_loc = (
            tainted_param.get("location", "QUERY").upper() if tainted_param else "QUERY"
        )
        param_name = tainted_param.get("name", "q") if tainted_param else "q"

        params_list = [
            {
                "location": param_loc,
                "name": param_name,
                "type": "string",
                "is_tainted_target": True,
                "marker_value": inert_marker,
            }
        ]

        if sibling_params:
            for sp in sibling_params:
                params_list.append(
                    {
                        "location": sp.get("location", param_loc),
                        "name": sp.get("name", "param"),
                        "type": "string",
                        "is_tainted_target": False,
                        "marker_value": sp.get("dummy", "dummyVal"),
                    }
                )

        if method == "GET" or param_loc == "QUERY":
            curl_cmd = (
                f'curl -G "${{TARGET_URL:-http://localhost:3000}}{route}"{auth_header} '
                f'--data-urlencode "{param_name}={inert_marker}"'
            )
        else:
            payload_dict = {param_name: inert_marker}
            if sibling_params:
                for sp in sibling_params:
                    payload_dict[sp.get("name", "sibling")] = sp.get("dummy", "dummyVal")
            json_body = json.dumps(payload_dict)
            curl_cmd = (
                f'curl -X {method} "${{TARGET_URL:-http://localhost:3000}}{route}"{auth_header} '
                f'-H "Content-Type: application/json" '
                f"-d '{json_body}'"
            )

        return {
            "reproduction_type": "HTTP_TEMPLATE",
            "method": method,
            "route": route,
            "auth_context": {
                "auth_state": auth_state,
                "header_placeholder": (
                    "Authorization: Bearer ${AUTH_TOKEN}"
                    if auth_state == "REQUIRED"
                    else None
                ),
            },
            "parameters": params_list,
            "expected_assertion": {
                "assertion_type": "PARAMETER_REACHABILITY",
                "description": (
                    f"Marker '{inert_marker}' propagates into server-side sink {sink_target}."
                ),
            },
            "curl_command": curl_cmd,
        }
