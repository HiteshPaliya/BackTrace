"""Composite exploitability risk scorer calculating reachability priorities."""

from typing import Dict, Optional


class CompositeScorer:
    """Calculates prioritized reachability scores based on severity, exposure, and complexity."""

    SEVERITY_WEIGHTS: Dict[str, float] = {
        "CRITICAL": 1.0,
        "HIGH": 0.8,
        "MEDIUM": 0.5,
        "LOW": 0.2,
        "INFO": 0.05,
    }

    SCOPE_FACTORS: Dict[str, float] = {
        "APPLICATION_RUNTIME": 1.0,
        "CLIENT_SPA": 0.8,
        "CI_CD_PIPELINE": 0.6,
        "INFRASTRUCTURE_IAC": 0.5,
        "TEST_MOCK": 0.1,
        "DATA_SEED_TUTORIAL": 0.05,
        "VENDOR_DEPENDENCY": 0.01,
        "BUILD_OUTPUT_GENERATED": 0.01,
    }

    @staticmethod
    def calculate_priority(
        sink_severity: str,
        reachability_confidence: float,
        is_unauthenticated: bool = True,
        hop_count: int = 1,
        auth_state: Optional[str] = None,
        execution_domain: Optional[str] = None,
    ) -> float:
        """Calculate composite priority score incorporating scope factor and tri-state exposure."""
        sev_weight = CompositeScorer.SEVERITY_WEIGHTS.get(sink_severity.upper(), 0.1)

        # Exposure Level
        if auth_state == "NOT_REQUIRED":
            exposure_multiplier = 1.5
        elif auth_state == "UNKNOWN":
            exposure_multiplier = 1.1
        elif auth_state == "REQUIRED":
            exposure_multiplier = 1.0
        else:
            exposure_multiplier = 1.5 if is_unauthenticated else 1.0

        # Scope Factor
        domain_key = (execution_domain or "APPLICATION_RUNTIME").upper()
        scope_factor = CompositeScorer.SCOPE_FACTORS.get(domain_key, 1.0)

        # Path complexity penalty
        complexity_penalty = max(1.0, float(max(1, hop_count)) ** 0.5)

        return (
            sev_weight
            * reachability_confidence
            * exposure_multiplier
            * scope_factor
        ) / complexity_penalty
