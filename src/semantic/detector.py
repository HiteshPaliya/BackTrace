"""Polyglot semantic detector matrix scanning for sources, transforms, and sinks."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from src.semantic.sinks import SemanticSink
from src.semantic.sources import SemanticSource
from src.semantic.transforms import SemanticTransform


@dataclass
class SemanticFileFindings:
    """Discovered sources, transforms, and candidate sinks within an individual file."""

    sources: List[SemanticSource] = field(default_factory=list)
    transforms: List[SemanticTransform] = field(default_factory=list)
    sinks: List[SemanticSink] = field(default_factory=list)


class SemanticDetector:
    """Detects sources, transforms, and sinks using polyglot semantic pattern matching."""

    SOURCE_PATTERNS = [
        (re.compile(r"""\b(?:req|request)\.body(?:\.[a-zA-Z0-9_$]+)?\b"""), "HTTP_BODY"),
        (re.compile(r"""\b(?:req|request)\.query(?:\.[a-zA-Z0-9_$]+)?\b"""), "HTTP_QUERY"),
        (re.compile(r"""\b(?:req|request)\.params(?:\.[a-zA-Z0-9_$]+)?\b"""), "HTTP_PARAMS"),
        (re.compile(r"""\b(?:req|request)\.headers(?:\.[a-zA-Z0-9_$]+)?\b"""), "HTTP_HEADERS"),
        (re.compile(r"""\b(?:req|request)\.cookies(?:\.[a-zA-Z0-9_$]+)?\b"""), "HTTP_COOKIES"),
    ]

    TRANSFORM_PATTERNS = [
        (re.compile(r"""\b(?:path|os\.path)\.join\s*\([^)]+\)"""), "PATH_CONSTRUCTION"),
        (
            re.compile(r"""\b(?:parseInt|Number|parseFloat|int|float)\s*\([^)]+\)"""),
            "TYPE_CONSTRAINT",
        ),
        (
            re.compile(r"""\b(?:decodeURIComponent|unquote|b64decode)\s*\([^)]+\)"""),
            "ENCODING_DECODING",
        ),
        (re.compile(r"""\b(?:sanitize|escapeHtml|DOMPurify)\s*\([^)]+\)"""), "SANITIZER"),
    ]

    SINK_PATTERNS = [
        # SSRF
        (
            re.compile(
                r"""\b(?:needle|axios|urllib\.request|requests)\.(?:get|post|put|delete|head)\s*\([^)]+\)"""
                r"""|\bfetch\s*\([^)]+\)|\brequest\s*\([^)]+\)"""
            ),
            "SSRF",
            "CRITICAL",
            "CWE-918",
            "HTTP_REQUEST",
        ),
        # XXE (Direct import or libxmljs call)
        (
            re.compile(
                r"""\b(?:libxmljs\.)?parseXmlString\s*\([^)]+\)"""
                r"""|\bxml2js\.parseString\s*\([^)]+\)|\betree\.fromstring\s*\([^)]+\)"""
            ),
            "XXE",
            "CRITICAL",
            "CWE-611",
            "XML_PARSING",
        ),
        # NoSQL Injection (Any collection/model receiver with query operator)
        (
            re.compile(
                r"""\b(?:[a-zA-Z0-9_$]+\.)+find(?:One)?\s*\(\s*\{.*?\$(?:where|regex)"""
            ),
            "NOSQLI",
            "HIGH",
            "CWE-943",
            "NOSQL_QUERY",
        ),
        # SQL Injection
        (
            re.compile(
                r"""\b(?:models\.)?sequelize\.query\s*\([^)]+\)|\bdb\.raw\s*\([^)]+\)"""
                r"""|\bcursor\.execute\s*\([^)]+\)"""
            ),
            "SQLI",
            "CRITICAL",
            "CWE-89",
            "SQL_EXECUTION",
        ),
        # Path Traversal
        (
            re.compile(
                r"""\b(?:res\.sendFile|fs\.readFile|fs\.readFileSync|open)\s*\([^)]+\)"""
            ),
            "PATH_TRAVERSAL",
            "HIGH",
            "CWE-22",
            "FILESYSTEM_ACCESS",
        ),
        # Command Execution & Code Evaluation (RCE)
        (
            re.compile(
                r"""\b(?:child_process\.exec|os\.system|os\.popen|subprocess\.(?:Popen|run|call)|"""
                r"""eval|vm\.runInContext|new\s+Function)\s*\([^)]+\)"""
            ),
            "RCE",
            "CRITICAL",
            "CWE-78",
            "COMMAND_EXECUTION",
        ),
        # Deserialization
        (
            re.compile(
                r"""\byaml\.load\s*\([^)]+\)|\bpickle\.loads\s*\([^)]+\)|\bunserialize\s*\([^)]+\)"""
            ),
            "DESERIALIZATION",
            "HIGH",
            "CWE-502",
            "OBJECT_DESERIALIZATION",
        ),
        # Template / DOM XSS
        (
            re.compile(
                r"""!=[^\n]+|\|\s*safe\b|\b(?:dangerouslySetInnerHTML|bypassSecurityTrustHtml|bypassSecurityTrustScript)\b"""
            ),
            "XSS",
            "HIGH",
            "CWE-79",
            "TEMPLATE_HTML_OUTPUT",
        ),
    ]

    def scan_source(self, file_path: Path | str, code: str, language: str) -> SemanticFileFindings:
        """Scan source code lines for sources, transforms, and sinks."""
        findings = SemanticFileFindings()
        f_str = str(file_path).replace("\\", "/")

        for idx, line in enumerate(code.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith(("//", "#", "/*", "*")):
                continue

            # 1. Sources
            for pattern, src_type in self.SOURCE_PATTERNS:
                for match in pattern.finditer(line_str):
                    findings.sources.append(
                        SemanticSource(
                            expression=match.group(0),
                            source_type=src_type,
                            line_number=idx,
                            file_path=f_str,
                        )
                    )

            # 2. Transforms
            for pattern, category in self.TRANSFORM_PATTERNS:
                for match in pattern.finditer(line_str):
                    findings.transforms.append(
                        SemanticTransform(
                            expression=match.group(0),
                            category=category,
                            line_number=idx,
                            file_path=f_str,
                        )
                    )

            # 3. Sinks with argument & language context evaluation
            is_template_file = f_str.endswith((".pug", ".jade", ".ejs"))
            for pattern, vuln_class, severity, cwe, context in self.SINK_PATTERNS:
                for match in pattern.finditer(line_str):
                    matched_expr = match.group(0)

                    # Invariant 2: Template unescape != is ONLY valid in template files
                    if matched_expr.startswith("!=") and not is_template_file:
                        continue

                    # Invariant 1: SSRF must NOT match Supertest or hardcoded string literals
                    arg_expr = None
                    if vuln_class == "SSRF":
                        if "request(app)" in matched_expr or "request(server)" in matched_expr:
                            continue
                        arg_match = re.search(r"""\(\s*([^,)]+)""", matched_expr)
                        if arg_match:
                            arg_expr = arg_match.group(1).strip()
                            is_lit = (
                                (arg_expr.startswith(("'", '"')) and arg_expr.endswith(("'", '"')))
                                or (arg_expr.startswith("`") and "${" not in arg_expr)
                            )
                            if is_lit:
                                continue

                    # Invariant 1: Path Traversal must NOT match hardcoded static paths
                    if vuln_class == "PATH_TRAVERSAL":
                        arg_match = re.search(r"""\(\s*([^,)]+)""", matched_expr)
                        if arg_match:
                            arg_expr = arg_match.group(1).strip()
                            is_lit = (
                                (arg_expr.startswith(("'", '"')) and arg_expr.endswith(("'", '"')))
                                or (arg_expr.startswith("`") and "${" not in arg_expr)
                            )
                            if is_lit and not re.search(r"""\$\{|\+|path\.join""", matched_expr):
                                continue

                    findings.sinks.append(
                        SemanticSink(
                            vuln_class=vuln_class,
                            expression=matched_expr,
                            triage_severity=severity,
                            line_number=idx,
                            file_path=f_str,
                            cwe_id=cwe,
                            sink_context=context,
                            argument_expression=arg_expr,
                            is_variable_argument=True,
                        )
                    )

        return findings
