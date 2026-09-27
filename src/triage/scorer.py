"""Composite exploitability risk scorer calculating reachability priorities."""

from typing import Dict


class CompositeScorer:
    """Calculates prioritized reachability scores based on severity, exposure, and complexity."""

    SEVERITY_WEIGHTS: Dict[str, float] = {
        "CRITICAL": 1.0,
        "HIGH": 0.8,
        "MEDIUM": 0.5,
        "LOW": 0.2,
        "INFO": 0.05,
    }

    @staticmethod
    def calculate_priority(
        sink_severity: str,
        reachability_confidence: float,
        is_unauthenticated: bool,
        hop_count: int,
    ) -> float:
        """Calculate composite priority score:

        Priority = (Sink Severity * Reachability Confidence * Exposure Level) / Path Complexity
        """
        sev_weight = CompositeScorer.SEVERITY_WEIGHTS.get(sink_severity.upper(), 0.1)
        exposure_multiplier = 1.5 if is_unauthenticated else 1.0
        complexity_penalty = max(1.0, float(max(1, hop_count)) ** 0.5)

        return (sev_weight * reachability_confidence * exposure_multiplier) / complexity_penalty
