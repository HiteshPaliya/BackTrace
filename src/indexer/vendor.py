"""Vendor code shallow signature harvester mapping external APIs to sink classes."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class VendorAPISignature:
    """Harvested signature of a 3rd-party library API call."""

    package_name: str
    api_name: str
    potential_sink_class: str
    signature_pattern: Optional[str] = None


class VendorSignatureHarvester:
    """Harvests exported APIs from vendor packages and tags dangerous sink classes."""

    SINK_RULES: Dict[str, str] = {
        r".*(query|rawquery|sql|execsql).*": "SQLI",
        r".*(exec|spawn|fork|popen|system|command).*": "RCE",
        r".*(fetch|request|http|axios|ssrf).*": "SSRF",
        r".*(readfile|writefile|unlink|traversal).*": "PATH_TRAVERSAL",
        r".*(eval|runincontext|compile).*": "CODE_INJECTION",
    }

    JS_EXPORT_PATTERN = re.compile(
        r"(?:exports\.|export\s+(?:function|const|let|var)\s+|module\.exports\s*=\s*{[^}]*?)(\b[a-zA-Z0-9_$]+\b)",
        re.MULTILINE,
    )
    PY_DEF_PATTERN = re.compile(
        r"def\s+([a-zA-Z0-9_]+)\s*\(",
        re.MULTILINE,
    )

    def _classify_api(self, api_name: str) -> Optional[str]:
        api_lower = api_name.lower()
        for pattern, vuln_class in self.SINK_RULES.items():
            if re.match(pattern, api_lower):
                return vuln_class
        return None

    def harvest(self, vendor_root: Path | str) -> List[VendorAPISignature]:
        """Shallow harvest of exported functions/APIs from vendor packages."""
        root = Path(vendor_root).resolve()
        if not root.is_dir():
            return []

        signatures: List[VendorAPISignature] = []

        # Enumerate package directories (handle scoped packages like @org/pkg)
        pkg_dirs: List[Path] = []
        for p in root.iterdir():
            if not p.is_dir():
                continue
            if p.name.startswith("@"):
                pkg_dirs.extend([sub for sub in p.iterdir() if sub.is_dir()])
            else:
                pkg_dirs.append(p)

        for pkg in pkg_dirs:
            package_name = pkg.relative_to(root).as_posix()
            # Shallow scan of entry files only (avoid recursive AST traversal)
            candidate_files = [
                pkg / "index.js",
                pkg / "main.js",
                pkg / "index.ts",
                pkg / "__init__.py",
                pkg / f"{pkg.name}.py",
            ]

            for file_path in candidate_files:
                if not file_path.is_file():
                    continue
                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                # Scan exports
                is_py = file_path.suffix == ".py"
                pattern = self.PY_DEF_PATTERN if is_py else self.JS_EXPORT_PATTERN

                for match in pattern.finditer(text):
                    api_name = match.group(1)
                    sink_class = self._classify_api(api_name)
                    if sink_class:
                        signatures.append(
                            VendorAPISignature(
                                package_name=package_name,
                                api_name=api_name,
                                potential_sink_class=sink_class,
                                signature_pattern=match.group(0).strip(),
                            )
                        )

        return signatures
