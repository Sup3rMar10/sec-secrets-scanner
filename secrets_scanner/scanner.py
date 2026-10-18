"""File-tree and diff scanning on top of detect.scan_lines."""
import os
from dataclasses import dataclass, field

from .detect import Config, scan_lines
from .diffparse import parse_diff
from .report import Finding

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", ".venv", "venv", ".mypy_cache"}
MAX_BYTES = 1_000_000


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    skipped: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    suppressed: int = 0
    expired: list = field(default_factory=list)


def display_path(path: str) -> str:
    try:
        path = os.path.relpath(path)
    except ValueError:
        pass
    return path.replace(os.sep, "/")


def iter_files(paths, res: ScanResult):
    for p in paths:
        if not os.path.exists(p):
            res.errors.append(f"not found: {p}")
        elif os.path.isfile(p):
            yield p
        else:
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS)
                for f in sorted(files):
                    yield os.path.join(root, f)


def scan_paths(paths, cfg: Config) -> ScanResult:
    res = ScanResult()
    for fp in iter_files(paths, res):
        try:
            if os.path.getsize(fp) > MAX_BYTES:
                res.skipped.append((display_path(fp), "too large"))
                continue
            with open(fp, "rb") as fh:
                data = fh.read()
        except OSError as e:
            res.errors.append(f"cannot read {display_path(fp)}: {e.strerror or e}")
            continue
        if b"\0" in data[:8192]:
            res.skipped.append((display_path(fp), "binary"))
            continue
        res.files_scanned += 1
        text = data.decode("utf-8", "replace")
        shown = display_path(fp)
        for no, m in scan_lines(enumerate(text.splitlines(), 1), cfg):
            res.findings.append(Finding.make(shown, no, m))
    return res


def scan_diff(diff_text: str, cfg: Config) -> ScanResult:
    """Scan only ADDED lines of a unified diff; findings carry new-file line numbers."""
    res = ScanResult()
    for path, lines in parse_diff(diff_text).items():
        res.files_scanned += 1
        for no, m in scan_lines(lines, cfg):
            res.findings.append(Finding.make(path, no, m))
    return res
