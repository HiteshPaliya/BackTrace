"""Tests for Multidimensional Scope Classifier and Source Hydrator."""

from pathlib import Path

from src.core.scope import ExecutionDomain, RuntimeRole, ScopeClassifier
from src.core.workspace import FileInfo, SourceHydrator


def test_multidimensional_scope_classification():
    """Happy path: Correctly assigns 4 orthogonal scope dimensions with confidence and evidence."""
    ci_file = FileInfo(
        rel_path=".github/workflows/ci.yml",
        abs_path="/repo/.github/workflows/ci.yml",
        language="yaml",
        is_vendor=False,
        file_hash="h1",
        loc=100,
    )
    spec_file = FileInfo(
        rel_path="frontend/src/app.spec.ts",
        abs_path="/repo/frontend/src/app.spec.ts",
        language="typescript",
        is_vendor=False,
        file_hash="h2",
        loc=50,
    )
    route_file = FileInfo(
        rel_path="routes/login.ts",
        abs_path="/repo/routes/login.ts",
        language="typescript",
        is_vendor=False,
        file_hash="h3",
        loc=80,
    )
    iac_file = FileInfo(
        rel_path="infra/main.tf",
        abs_path="/repo/infra/main.tf",
        language="terraform",
        is_vendor=False,
        file_hash="h4",
        loc=30,
    )

    classifier = ScopeClassifier()
    ci_meta = classifier.classify(ci_file)
    spec_meta = classifier.classify(spec_file)
    route_meta = classifier.classify(route_file)
    iac_meta = classifier.classify(iac_file)

    assert ci_meta.execution_domain == ExecutionDomain.CI_CD_PIPELINE
    assert spec_meta.execution_domain == ExecutionDomain.TEST_MOCK
    assert route_meta.execution_domain == ExecutionDomain.APPLICATION_RUNTIME
    assert route_meta.runtime_role == RuntimeRole.ROUTE_HANDLER
    assert iac_meta.execution_domain == ExecutionDomain.INFRASTRUCTURE_IAC
    assert route_meta.confidence >= 0.90
    assert len(route_meta.evidence) > 0


def test_source_hydrator_resolves_redacted_lines(tmp_path: Path):
    """Happy path: Replaces 'requires login' with real line from filesystem."""
    target = tmp_path / "routes" / "search.ts"
    target.parent.mkdir(parents=True)
    target.write_text("line 1\nmodels.sequelize.query(criteria)\nline 3\n", encoding="utf-8")

    hydrator = SourceHydrator(tmp_path)
    snippet = hydrator.hydrate_snippet("routes/search.ts", 2, "requires login")
    assert "models.sequelize.query(criteria)" in snippet


def test_source_hydrator_handles_missing_file_gracefully(tmp_path: Path):
    """Boundary test: Missing file falls back safely to original snippet."""
    hydrator = SourceHydrator(tmp_path)
    snippet = hydrator.hydrate_snippet("nonexistent.ts", 10, "fallback snippet")
    assert snippet == "fallback snippet"
