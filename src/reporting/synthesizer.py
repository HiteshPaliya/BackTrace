"""Dossier synthesizer compiling verified taint paths into research dossiers."""

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
