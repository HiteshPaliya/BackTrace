"""Track B Authorization Relationship Analyzer (BOLA / IDOR)."""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthzAnalysisResult:
    """Result of analyzing route handler for object-level authorization relationships."""

    has_gap: bool
    gap_type: Optional[str] = None  # 'CANDIDATE_AUTHZ_GAP'
    status: str = "NO_OBJECT_KEY"    # 'AUTHZ_CONSTRAINT_PRESENT', 'NO_OBJECT_KEY', 'UNRESOLVED'
    object_key: Optional[str] = None
    principal_expr: Optional[str] = None
    retrieval_op: Optional[str] = None
    relationship_type: str = "NONE" # 'OWNER', 'TENANT', 'ROLE', 'PERMISSION'


class AuthorizationAnalyzer:
    """Analyzes entity retrievals for missing principal-to-object authorization constraints."""

    OBJECT_PARAM_PATTERN = re.compile(r"""\breq\.params\.(?:[a-zA-Z0-9_$]*id|id)\b""")
    PRINCIPAL_PATTERN = re.compile(
        r"""\b(?:req\.user\.id|token\.sub|session\.userId|current_user\.id|req\.user\.tenantId)\b"""
    )
    UNSCOPED_LOOKUP_PATTERN = re.compile(
        r"""\b([A-Z][a-zA-Z0-9_]*)\.(?:findByPk|findById|findOne|find|get)\s*\(""",
        re.IGNORECASE,
    )
    SCOPED_QUERY_PATTERN = re.compile(
        r"""\b([A-Z][a-zA-Z0-9_]*)\.(?:findOne|find|findAll|filter)\s*\(.*?\b(?:userId|ownerid|tenantid)\b""",
        re.IGNORECASE | re.DOTALL,
    )
    POST_FETCH_GUARD_PATTERN = re.compile(
        r"""if\s*\([^)]*(?:userId|ownerid|tenantid)[^)]*!==?[^)]*req\.user\.id[^)]*\)""",
        re.IGNORECASE,
    )

    def analyze_handler(
        self,
        method: str,
        route_pattern: str,
        code: str,
        language: str = "javascript",
    ) -> AuthzAnalysisResult:
        """Evaluate route handler for missing authorization relationship bindings."""
        # 1. Identify target resource key
        has_route_id = any(tok in route_pattern for tok in [":id", ":basketId", ":orderId"])
        param_match = self.OBJECT_PARAM_PATTERN.search(code)
        fallback_key = "req.params.id" if has_route_id else None
        object_key = param_match.group(0) if param_match else fallback_key

        if not object_key and not has_route_id:
            return AuthzAnalysisResult(has_gap=False, status="NO_OBJECT_KEY")

        # 2. Check for query scoping (safe scoped lookup)
        if self.SCOPED_QUERY_PATTERN.search(code):
            return AuthzAnalysisResult(
                has_gap=False,
                status="AUTHZ_CONSTRAINT_PRESENT",
                object_key=object_key,
                relationship_type="OWNER",
            )

        # 3. Check for post-retrieval ownership assertions
        if self.POST_FETCH_GUARD_PATTERN.search(code):
            return AuthzAnalysisResult(
                has_gap=False,
                status="AUTHZ_CONSTRAINT_PRESENT",
                object_key=object_key,
                relationship_type="OWNER",
            )

        # 4. Check for unscoped lookups (excluding HTTP framework handlers)
        for unscoped_match in self.UNSCOPED_LOOKUP_PATTERN.finditer(code):
            entity_model = unscoped_match.group(1)
            if entity_model.lower() in (
                "app",
                "router",
                "express",
                "req",
                "request",
                "res",
                "response",
            ):
                continue
            op_name = f"{entity_model}.lookup"
            return AuthzAnalysisResult(
                has_gap=True,
                gap_type="CANDIDATE_AUTHZ_GAP",
                status="MISSING_AUTHZ_PREDICATE",
                object_key=object_key,
                principal_expr="req.user.id",
                retrieval_op=op_name,
                relationship_type="OWNER",
            )

        return AuthzAnalysisResult(has_gap=False, status="NO_OBJECT_KEY")
