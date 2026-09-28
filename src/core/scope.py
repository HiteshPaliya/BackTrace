"""Multidimensional scope classification engine for repository files."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from src.core.workspace import FileInfo


class ExecutionDomain(str, Enum):
    """Primary execution environment for the file."""

    APPLICATION_RUNTIME = "APPLICATION_RUNTIME"
    CLIENT_SPA = "CLIENT_SPA"
    CI_CD_PIPELINE = "CI_CD_PIPELINE"
    INFRASTRUCTURE_IAC = "INFRASTRUCTURE_IAC"
    TEST_MOCK = "TEST_MOCK"
    DATA_SEED_TUTORIAL = "DATA_SEED_TUTORIAL"
    VENDOR_DEPENDENCY = "VENDOR_DEPENDENCY"
    BUILD_OUTPUT_GENERATED = "BUILD_OUTPUT_GENERATED"


class RuntimeRole(str, Enum):
    """Functional role of symbols within the file."""

    ROUTE_HANDLER = "ROUTE_HANDLER"
    MIDDLEWARE = "MIDDLEWARE"
    SERVICE_BUSINESS_LOGIC = "SERVICE_BUSINESS_LOGIC"
    DATA_ACCESS_ORM = "DATA_ACCESS_ORM"
    UTILITY_HELPER = "UTILITY_HELPER"
    CONFIGURATION = "CONFIGURATION"
    UNKNOWN = "UNKNOWN"


class Environment(str, Enum):
    """Runtime target environment."""

    PRODUCTION = "PRODUCTION"
    TEST = "TEST"
    DEVELOPMENT = "DEVELOPMENT"
    BUILD_TIME = "BUILD_TIME"


@dataclass
class ScopeMetadata:
    """Multidimensional classification metadata for a repository file."""

    execution_domain: ExecutionDomain
    runtime_role: RuntimeRole
    environment: Environment
    artifact_type: str
    confidence: float
    evidence: str


class ScopeClassifier:
    """Classifies files across 4 orthogonal dimensions with calibrated confidence and evidence."""

    def classify(self, file_info: FileInfo) -> ScopeMetadata:
        """Classify file_info into multidimensional scope dimensions."""
        rel_posix = file_info.rel_path.replace("\\", "/").lower()
        ext = Path(file_info.rel_path).suffix.lower()
        artifact_type = (file_info.language or ext.lstrip(".") or "unknown").upper()

        # 1. Vendor Dependency
        is_vendor_dir = any(
            p in rel_posix for p in ["node_modules/", "vendor/", "site-packages/"]
        )
        if file_info.is_vendor or is_vendor_dir:
            return ScopeMetadata(
                execution_domain=ExecutionDomain.VENDOR_DEPENDENCY,
                runtime_role=RuntimeRole.UTILITY_HELPER,
                environment=Environment.BUILD_TIME,
                artifact_type=artifact_type,
                confidence=1.0,
                evidence="Path matches vendor dependency directory",
            )

        # 2. CI/CD Workflows
        if any(p in rel_posix for p in [".github/", ".gitlab-ci", "jenkinsfile", ".circleci/"]):
            return ScopeMetadata(
                execution_domain=ExecutionDomain.CI_CD_PIPELINE,
                runtime_role=RuntimeRole.CONFIGURATION,
                environment=Environment.BUILD_TIME,
                artifact_type=artifact_type,
                confidence=0.98,
                evidence="Path matches CI/CD pipeline workflow directory",
            )

        # 3. Infrastructure as Code (IaC)
        if ext in [".tf", ".hcl", ".tfvars"] or "dockerfile" in rel_posix or "k8s/" in rel_posix:
            return ScopeMetadata(
                execution_domain=ExecutionDomain.INFRASTRUCTURE_IAC,
                runtime_role=RuntimeRole.CONFIGURATION,
                environment=Environment.BUILD_TIME,
                artifact_type=artifact_type,
                confidence=0.95,
                evidence=f"File extension or pattern '{ext}' matches Infrastructure as Code",
            )

        # 4. Test & Mock Code
        if any(p in rel_posix for p in [".spec.", ".test.", "tests/", "__tests__/", "fixtures/"]):
            return ScopeMetadata(
                execution_domain=ExecutionDomain.TEST_MOCK,
                runtime_role=RuntimeRole.UTILITY_HELPER,
                environment=Environment.TEST,
                artifact_type=artifact_type,
                confidence=0.95,
                evidence="Path or filename matches test specification convention",
            )

        # 5. Data Seeds & Tutorial / Codefixes
        if any(p in rel_posix for p in ["codefixes/", "data/static/challenges", "seeds/"]):
            return ScopeMetadata(
                execution_domain=ExecutionDomain.DATA_SEED_TUTORIAL,
                runtime_role=RuntimeRole.UTILITY_HELPER,
                environment=Environment.TEST,
                artifact_type=artifact_type,
                confidence=0.90,
                evidence="Directory matches static seed or tutorial coding challenges",
            )

        # 6. Frontend / Client SPA
        if any(p in rel_posix for p in ["frontend/", "client/", "static/", "public/", "views/"]):
            return ScopeMetadata(
                execution_domain=ExecutionDomain.CLIENT_SPA,
                runtime_role=RuntimeRole.UTILITY_HELPER,
                environment=Environment.PRODUCTION,
                artifact_type=artifact_type,
                confidence=0.90,
                evidence="Directory path matches frontend client SPA structure",
            )

        # 7. Application Runtime - Sub-role identification
        role = RuntimeRole.UNKNOWN
        evidence = "Default application runtime classification"
        if any(p in rel_posix for p in ["routes/", "controllers/", "api/", "endpoints/"]):
            role = RuntimeRole.ROUTE_HANDLER
            evidence = "Directory matches web application route/controller handler"
        elif any(p in rel_posix for p in ["middleware/", "guards/", "interceptors/"]):
            role = RuntimeRole.MIDDLEWARE
            evidence = "Directory matches middleware/guard pattern"
        elif any(p in rel_posix for p in ["services/", "domain/", "usecases/"]):
            role = RuntimeRole.SERVICE_BUSINESS_LOGIC
            evidence = "Directory matches service business logic pattern"
        elif any(p in rel_posix for p in ["models/", "entities/", "repositories/", "repos/"]):
            role = RuntimeRole.DATA_ACCESS_ORM
            evidence = "Directory matches model/data-access ORM pattern"

        return ScopeMetadata(
            execution_domain=ExecutionDomain.APPLICATION_RUNTIME,
            runtime_role=role,
            environment=Environment.PRODUCTION,
            artifact_type=artifact_type,
            confidence=0.92 if role != RuntimeRole.UNKNOWN else 0.75,
            evidence=evidence,
        )
