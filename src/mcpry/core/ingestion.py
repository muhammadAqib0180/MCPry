"""
MCPry core ingestion — file discovery and repository acquisition.

Responsibilities:
  - Accept a local path or GitHub URL as the scan target
  - Clone remote repositories via GitPython into a temp directory
  - Walk the file tree, skip noise dirs, respect size limits
  - Produce a FileManifest with fully-loaded ScannedFile objects
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from mcpry.config import (
    ALL_SCANNABLE_EXTENSIONS,
    JS_TS_EXTENSIONS,
    JSON_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    PYTHON_EXTENSIONS,
    SKIP_DIRS,
    TEMP_CLONE_DIR,
)
from mcpry.models import FileManifest, ScannedFile

# ── GitHub URL detection ──────────────────────────────────────────────────────

_GITHUB_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/[\w\-]+/[\w\-\.]+(?:\.git)?(?:/.*)?$",
    re.IGNORECASE,
)


def is_github_url(target: str) -> bool:
    """Return True if *target* looks like a GitHub repository URL."""
    return bool(_GITHUB_RE.match(target.strip()))


# ── Language detection ────────────────────────────────────────────────────────


def _detect_language(path: Path) -> Optional[str]:
    """Map a file extension to a language string, or None if not scannable."""
    ext = path.suffix.lower()
    if ext in PYTHON_EXTENSIONS:
        return "python"
    if ext in JS_TS_EXTENSIONS:
        return "javascript" if ext in {".js", ".mjs", ".cjs"} else "typescript"
    if ext in JSON_EXTENSIONS:
        return "json"
    return None


# ── Core walker ───────────────────────────────────────────────────────────────


def _walk_directory(root: Path) -> list[ScannedFile]:
    """Recursively walk *root* and return ScannedFile objects for scannable files."""
    files: list[ScannedFile] = []

    for path in root.rglob("*"):
        # Skip directories and non-files
        if not path.is_file():
            continue

        # Skip noise directories anywhere in the path
        if any(part in SKIP_DIRS for part in path.parts):
            continue

        language = _detect_language(path)
        if language is None:
            continue

        size = path.stat().st_size
        if size > MAX_FILE_SIZE_BYTES:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        files.append(
            ScannedFile(
                path=str(path),
                relative_path=str(path.relative_to(root)),
                language=language,
                size_bytes=size,
                content=content,
            )
        )

    return files


# ── GitHub cloning ────────────────────────────────────────────────────────────


def _clone_github_repo(url: str) -> Path:
    """
    Clone a GitHub repository to a unique temp directory and return its path.

    Uses GitPython. Raises RuntimeError if cloning fails.
    """
    try:
        import git  # gitpython
    except ImportError as exc:
        raise RuntimeError(
            "GitPython is required to scan GitHub repositories. "
            "Install it with: pip install gitpython"
        ) from exc

    TEMP_CLONE_DIR.mkdir(parents=True, exist_ok=True)

    # Create a unique subdirectory for this clone so parallel scans don't clash
    clone_dir = Path(tempfile.mkdtemp(dir=TEMP_CLONE_DIR))

    try:
        git.Repo.clone_from(url, clone_dir, depth=1)
    except git.exc.GitCommandError as exc:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to clone {url!r}: {exc}") from exc

    return clone_dir


# ── Public API ────────────────────────────────────────────────────────────────


def ingest(target: str) -> tuple[FileManifest, Optional[Path]]:
    """
    Ingest a scan target and return a (FileManifest, clone_dir) tuple.

    Parameters
    ----------
    target:
        Either a local filesystem path or a GitHub repository URL.

    Returns
    -------
    manifest:
        Populated FileManifest containing all discovered ScannedFile objects.
    clone_dir:
        The temporary directory created when cloning a remote repo, or None
        for local targets. Callers are responsible for cleanup.
    """
    clone_dir: Optional[Path] = None
    is_git = False

    if is_github_url(target):
        clone_dir = _clone_github_repo(target)
        root = clone_dir
        is_git = True
    else:
        root = Path(target).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Target path does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Target must be a directory, got: {root}")
        # Check if it's also a git repo (informational only)
        is_git = (root / ".git").is_dir()

    files = _walk_directory(root)

    manifest = FileManifest(
        target_path=str(root),
        is_git_repo=is_git,
        files=files,
    )

    return manifest, clone_dir
