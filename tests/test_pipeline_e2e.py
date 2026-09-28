"""Tests for authoritative semantic CPG pipeline integration and version gating."""

from pathlib import Path

from click.testing import CliRunner

from src.cli import cli
from src.storage.db import DatabaseManager


def test_full_backtrace_pipeline_on_synthetic_repo(tmp_path: Path):
    """Happy path: Pipeline discovers routes, resolves SSRF flow, outputs inert blueprint."""
    app_file = tmp_path / "app.js"
    app_file.write_text(
        """
        const express = require('express');
        const needle = require('needle');
        const app = express();
        app.get('/api/fetch', (req, res) => {
            const url = req.query.url;
            needle.get(url);
        });
        """,
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 0
    assert "Scan completed successfully" in res.output

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    with db._get_connection() as conn:
        q = "SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1;"
        scans = conn.execute(q).fetchone()
        scan_id = scans["scan_id"]

    dossiers = db.get_scan_dossiers(scan_id)
    assert len(dossiers) >= 1
    ssrf_dossier = next((d for d in dossiers if d["vuln_class"] == "SSRF"), None)
    assert ssrf_dossier is not None
    assert ssrf_dossier["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE_PARTIAL_SANITIZATION")
    assert "BT_FLOW_MARKER_001" in ssrf_dossier["repro_curl_template"]


def test_bola_detection_in_pipeline(tmp_path: Path):
    """Happy path: End-to-end pipeline discovers unscoped query and emits BOLA/IDOR dossier."""
    app_file = tmp_path / "server.js"
    app_file.write_text(
        """
        const express = require('express');
        const app = express();
        app.get('/rest/basket/:id', (req, res) => {
            const basketId = req.params.id;
            Basket.findByPk(basketId).then(basket => {
                res.json(basket);
            });
        });
        """,
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 0

    db = DatabaseManager(tmp_path / ".audit" / "audit.db")
    with db._get_connection() as conn:
        q = "SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1;"
        scans = conn.execute(q).fetchone()
        scan_id = scans["scan_id"]

    dossiers = db.get_scan_dossiers(scan_id)
    bola_dossier = next(
        (d for d in dossiers if d["vuln_class"] in ("BOLA_IDOR", "AUTHZ_GAP")),
        None,
    )
    assert bola_dossier is not None
    assert "basket" in bola_dossier["title"].lower()
