import os
import random
import subprocess
import sys
from pathlib import Path

from secrets_scanner.corpus import make_token
from secrets_scanner.detect import Config, scan_lines

ROOT = Path(__file__).resolve().parents[1]


def tok(rule, seed=0):
    """A fake credential-shaped token assembled at runtime (never written to the repo)."""
    return make_token(rule, random.Random(seed))


def scan_text(text, **cfg):
    return scan_lines(enumerate(text.splitlines(), 1), Config(**cfg))


def run_cli(*args, cwd=None, stdin=None):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "secrets_scanner", *map(str, args)], cwd=str(cwd or ROOT),
                          input=stdin, capture_output=True, text=True, env=env, timeout=120)
