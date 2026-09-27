"""Incremental Git-diff engine with working tree support and version gating."""

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from src.storage.db import DatabaseManager


@dataclass
class DiffImpactPlan:
    """Calculated impact plan for incremental scanning."""

    changed_files: List[Path]
    unaffected_files: List[Path]
    engine_fingerprint: str
    reusable_dossier_ids: List[str] = field(default_factory=list)


class GitDiffEngine:
    """Analyzes Git diffs (including unstaged and untracked files) with engine version gating."""

    def __init__(self, repo_path: Path | str, db_manager: DatabaseManager) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.db = db_manager

    def compute_engine_fingerprint(self, config: Dict[str, Any]) -> str:
        """Compute deterministic SHA256 engine fingerprint based on config, rules, and models."""
        canonical_json = json.dumps(config, sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def _is_git_repo(self) -> bool:
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                check=False,
            )
            return res.returncode == 0
        except OSError:
            return False

    def compute_impact(
        self,
        base_ref: str = "HEAD",
        current_config: Optional[Dict[str, Any]] = None,
    ) -> DiffImpactPlan:
        """Identify changed files (working-tree + untracked) and validate version gating."""
        cfg = current_config or {}
        curr_fingerprint = self.compute_engine_fingerprint(cfg)

        if not self._is_git_repo():
            # Fallback for non-git workspaces: treat all files as changed
            all_files = [
                p for p in self.repo_path.rglob("*") if p.is_file() and ".audit" not in p.parts
            ]
            return DiffImpactPlan(
                changed_files=all_files,
                unaffected_files=[],
                engine_fingerprint=curr_fingerprint,
                reusable_dossier_ids=[],
            )

        changed_rel_paths: Set[str] = set()

        # 1. Capture modified, unstaged, and staged files relative to base_ref
        try:
            diff_proc = subprocess.run(
                ["git", "diff", "--name-only", base_ref],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                check=False,
            )
            for line in diff_proc.stdout.splitlines():
                if line.strip():
                    changed_rel_paths.add(line.strip().replace("\\", "/"))
        except OSError:
            pass

        # 2. Capture untracked files
        try:
            untracked_proc = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                check=False,
            )
            for line in untracked_proc.stdout.splitlines():
                if line.strip():
                    changed_rel_paths.add(line.strip().replace("\\", "/"))
        except OSError:
            pass

        changed_files = [
            self.repo_path / rel
            for rel in changed_rel_paths
            if (self.repo_path / rel).is_file()
        ]

        # 3. Query all indexed files in DB to determine unaffected files
        indexed_files = self.db.get_all_files()
        unaffected_files = [
            self.repo_path / f["rel_path"]
            for f in indexed_files
            if f["rel_path"].replace("\\", "/") not in changed_rel_paths
        ]

        # 4. Strict Version Gating: Check reusable dossiers
        reusable_ids: List[str] = []
        with self.db._get_connection() as conn:
            query = """
                SELECT d.dossier_id, f.rel_path
                FROM scan_dossiers d
                JOIN scan_candidate_paths p ON d.path_id = p.path_id
                JOIN candidate_sinks s ON p.sink_id = s.sink_id
                JOIN files f ON s.file_id = f.file_id
                WHERE d.engine_fingerprint = ?;
            """
            rows = conn.execute(query, (curr_fingerprint,)).fetchall()
            for r in rows:
                rel = r["rel_path"].replace("\\", "/")
                if rel not in changed_rel_paths:
                    reusable_ids.append(r["dossier_id"])

        return DiffImpactPlan(
            changed_files=changed_files,
            unaffected_files=unaffected_files,
            engine_fingerprint=curr_fingerprint,
            reusable_dossier_ids=reusable_ids,
        )
