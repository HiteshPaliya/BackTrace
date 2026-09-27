"""Tests for shallow Vendor Code Signature Harvester."""

from pathlib import Path

from src.indexer.vendor import VendorSignatureHarvester


def test_vendor_signature_harvesting(tmp_path: Path):
    """Happy path: Harvest exported dangerous API sinks from node_modules package."""
    pkg_dir = tmp_path / "node_modules" / "db-helper"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "index.js").write_text(
        "exports.rawQuery = function(sql) { return db.run(sql); };\n"
        "exports.safeMethod = function() { return 1; };\n",
        encoding="utf-8",
    )

    harvester = VendorSignatureHarvester()
    signatures = harvester.harvest(tmp_path / "node_modules")

    matched = [s for s in signatures if s.api_name == "rawQuery"]
    assert len(matched) == 1
    assert matched[0].potential_sink_class == "SQLI"
    assert matched[0].package_name == "db-helper"


def test_vendor_harvester_python_package(tmp_path: Path):
    """Happy path: Harvest dangerous API sinks from python vendor package."""
    pkg_dir = tmp_path / "site-packages" / "cmd_runner"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text(
        "def exec_command(cmd):\n    import os\n    return os.system(cmd)\n",
        encoding="utf-8",
    )

    harvester = VendorSignatureHarvester()
    signatures = harvester.harvest(tmp_path / "site-packages")

    matched = [s for s in signatures if s.api_name == "exec_command"]
    assert len(matched) == 1
    assert matched[0].potential_sink_class == "RCE"


def test_vendor_harvester_empty_or_missing(tmp_path: Path):
    """Boundary test: Missing vendor dir returns empty list safely."""
    harvester = VendorSignatureHarvester()
    signatures = harvester.harvest(tmp_path / "non_existent")
    assert signatures == []
