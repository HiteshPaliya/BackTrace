"""Evidence-based framework identification from manifests, lockfiles, and imports."""

import json
from pathlib import Path
from typing import Optional


class FrameworkDetector:
    """Detects active web framework from package manifests, lockfiles, and imports."""

    def __init__(self, repo_path: Path | str) -> None:
        self.repo_path = Path(repo_path).resolve()

    def identify(self) -> Optional[str]:
        """Identify the primary web framework used in the repository."""
        # 1. Node.js frameworks via package.json and lockfiles
        pkg_json = self.repo_path / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if "express" in deps:
                    return "express"
                if "@nestjs/core" in deps:
                    return "nestjs"
                if "fastify" in deps:
                    return "fastify"
                if "koa" in deps:
                    return "koa"
            except Exception:
                pass

        for lockfile in ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"]:
            lf_path = self.repo_path / lockfile
            if lf_path.is_file():
                try:
                    text = lf_path.read_text(encoding="utf-8", errors="replace").lower()
                    if "express" in text:
                        return "express"
                    if "fastify" in text:
                        return "fastify"
                    if "@nestjs/core" in text:
                        return "nestjs"
                except Exception:
                    pass

        # 2. Python frameworks via requirements.txt, pyproject.toml, or poetry.lock
        req_txt = self.repo_path / "requirements.txt"
        if req_txt.is_file():
            try:
                content = req_txt.read_text(encoding="utf-8", errors="replace").lower()
                if "fastapi" in content:
                    return "fastapi"
                if "django" in content:
                    return "django"
                if "flask" in content:
                    return "flask"
            except Exception:
                pass

        for py_conf in ["poetry.lock", "pyproject.toml", "Pipfile"]:
            py_path = self.repo_path / py_conf
            if py_path.is_file():
                try:
                    text = py_path.read_text(encoding="utf-8", errors="replace").lower()
                    if "fastapi" in text:
                        return "fastapi"
                    if "django" in text:
                        return "django"
                    if "flask" in text:
                        return "flask"
                except Exception:
                    pass

        # 3. Source code scanning heuristics (imports)
        for p in self.repo_path.rglob("*"):
            if not p.is_file() or any(
                part in [".git", "node_modules", ".venv"] for part in p.parts
            ):
                continue
            if p.suffix in [".js", ".ts"]:
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    has_express = (
                        "require('express')" in text
                        or 'from "express"' in text
                        or "express()" in text
                    )
                    if has_express:
                        return "express"
                except Exception:
                    pass

        return None
