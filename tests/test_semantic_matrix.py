"""Tests for Track A Semantic Source, Transform, and Sink Detector Matrix."""

from src.semantic.detector import SemanticDetector


def test_semantic_detectors_capture_ssrf_xxe_nosqli():
    """Happy path: Captures SSRF, XXE, NoSQLi, and distinguishes path.join transform from sink."""
    js_code = """
        const needle = require('needle');
        const libxmljs = require('libxmljs');
        const User = require('./models/user');

        function handleSsrf(req, res) {
            const targetUrl = req.query.url;
            needle.get(targetUrl); // SSRF Sink
        }

        function handleXxe(req, res) {
            const xml = req.body.xml;
            libxmljs.parseXmlString(xml, { noent: true }); // XXE Sink
        }

        function handleNoSql(req, res) {
            User.find({ $where: req.body.selector }); // NoSQL Injection Sink
        }
    """
    detector = SemanticDetector()
    findings = detector.scan_source("routes/test.js", js_code, "javascript")

    sink_types = {s.vuln_class for s in findings.sinks}
    assert "SSRF" in sink_types
    assert "XXE" in sink_types
    assert "NOSQLI" in sink_types

    # Verify sources extracted
    source_names = {src.expression for src in findings.sources}
    assert any("req.query.url" in s or "req.query" in s for s in source_names)

    # Path join must be classified as a transform, NOT a sink
    path_code = "const p = path.join(base, req.params.file); fs.readFile(p);"
    path_findings = detector.scan_source("routes/file.js", path_code, "javascript")
    assert any(t.category == "PATH_CONSTRUCTION" for t in path_findings.transforms)
    assert any(s.vuln_class == "PATH_TRAVERSAL" for s in path_findings.sinks)


def test_template_xss_and_deserialization():
    """Happy path: Captures template XSS and unsafe deserialization."""
    pug_code = "div!= userSuppliedComment"
    yaml_code = "const obj = yaml.load(userSuppliedYaml);"

    detector = SemanticDetector()
    pug_findings = detector.scan_source("views/comment.pug", pug_code, "javascript")
    yaml_findings = detector.scan_source("lib/loader.js", yaml_code, "javascript")

    assert any(s.vuln_class == "XSS" for s in pug_findings.sinks)
    assert any(s.vuln_class == "DESERIALIZATION" for s in yaml_findings.sinks)
