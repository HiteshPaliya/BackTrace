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


def test_semantic_invariants_reject_literals_and_supertest():
    """Invariants 1 & 2: Hardcoded literals, Supertest, and JS !== are NEVER sinks."""
    js_code = """
        const request = require('supertest');
        // Supertest call in tests
        request(app).get('/api/users');
        // Hardcoded static URL
        fetch("https://pastebin.com/static_hash");
        fetch('/rest/admin/application-configuration');
        // Hardcoded static file path
        fs.readFileSync('./swagger.yml', 'utf8');
        // Standard JS comparison operator
        if (value !== undefined) { doSomething(); }
    """
    detector = SemanticDetector()
    findings = detector.scan_source("app.js", js_code, "javascript")

    assert len(findings.sinks) == 0


def test_nosqli_lowercase_collection_and_direct_xxe_import():
    """Invariants 5 & 6: Lowercase collections and direct XML imports are detected."""
    js_code = """
        // Juice Shop trackOrder scenario: lowercase collection name
        db.ordersCollection.find({ $where: `this.orderId === '${id}'` });
        // Direct import XML parsing
        parseXmlString(untrustedData);
    """
    detector = SemanticDetector()
    findings = detector.scan_source("routes/trackOrder.js", js_code, "javascript")

    sink_types = {s.vuln_class for s in findings.sinks}
    assert "NOSQLI" in sink_types
    assert "XXE" in sink_types


def test_polyglot_python_and_code_eval_sinks():
    """Spec 6.1: Detects code evaluation (eval/Function) and polyglot Python sinks."""
    py_code = """
        import requests
        import subprocess

        def run_check(user_url, user_cmd):
            requests.get(user_url)
            subprocess.run(user_cmd, shell=True)
    """
    js_code = """
        function runCode(userCode) {
            eval(userCode);
            new Function(userCode)();
        }
    """
    detector = SemanticDetector()
    py_findings = detector.scan_source("app.py", py_code, "python")
    js_findings = detector.scan_source("evaluator.js", js_code, "javascript")

    py_sinks = {s.vuln_class for s in py_findings.sinks}
    assert "SSRF" in py_sinks
    assert "RCE" in py_sinks

    js_sinks = {s.vuln_class for s in js_findings.sinks}
    assert "RCE" in js_sinks

