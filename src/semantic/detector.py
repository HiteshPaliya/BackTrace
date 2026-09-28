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
            re.compile(r"""\b(?:needle|axios|urllib\.request)\.(?:get|post|put|delete|head)\s*\([^)]+\)|\bfetch\s*\([^)]+\)|\brequest\s*\([^)]+\)"""),
            "SSRF",
            "CRITICAL",
            "CWE-918",
            "HTTP_REQUEST",
        ),
        # XXE
        (
            re.compile(r"""\blibxmljs\.parseXmlString\s*\([^)]+\)|\bxml2js\.parseString\s*\([^)]+\)|\betree\.fromstring\s*\([^)]+\)"""),
            "XXE",
            "CRITICAL",
            "CWE-611",
            "XML_PARSING",
        ),
        # NoSQL Injection
        (
            re.compile(r"""\b[A-Z][a-zA-Z0-9_]*\.find(?:One)?\s*\(\s*\{[^}]*\$(?:where|regex)[^}]*\}\s*\)"""),
            "NOSQLI",
            "HIGH",
            "CWE-943",
            "NOSQL_QUERY",
        ),
        # SQL Injection
        (
            re.compile(r"""\b(?:models\.)?sequelize\.query\s*\([^)]+\)|\bdb\.raw\s*\([^)]+\)|\bcursor\.execute\s*\([^)]+\)"""),
            "SQLI",
            "CRITICAL",
            "CWE-89",
            "SQL_EXECUTION",
        ),
        # Path Traversal
        (
            re.compile(r"""\b(?:res\.sendFile|fs\.readFile|fs\.readFileSync|open)\s*\([^)]+\)"""),
            "PATH_TRAVERSAL",
            "HIGH",
            "CWE-22",
            "FILESYSTEM_ACCESS",
        ),
        # Command Execution (RCE)
        (
            re.compile(r"""\b(?:child_process\.exec|os\.system|subprocess\.Popen)\s*\([^)]+\)"""),
            "RCE",
            "CRITICAL",
            "CWE-78",
            "COMMAND_EXECUTION",
        ),
        # Deserialization
        (
            re.compile(r"""\byaml\.load\s*\([^)]+\)|\bpickle\.loads\s*\([^)]+\)|\bunserialize\s*\([^)]+\)"""),
            "DESERIALIZATION",
            "HIGH",
            "CWE-502",
            "OBJECT_DESERIALIZATION",
        ),
        # Template / HTML XSS
        (
            re.compile(r"""!=[^\n]+|dangerouslySetInnerHTML|\|\s*safe\b"""),
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

            # 3. Sinks
            for pattern, vuln_class, severity, cwe, context in self.SINK_PATTERNS:
                for match in pattern.finditer(line_str):
                    findings.sinks.append(
                        SemanticSink(
                            vuln_class=vuln_class,
                            expression=match.group(0),
                            triage_severity=severity,
                            line_number=idx,
                            file_path=f_str,
                            cwe_id=cwe,
                            sink_context=context,
                        )
                    )

        return findings
