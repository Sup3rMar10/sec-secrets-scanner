import json
import re
import shutil
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from secrets_scanner.corpus import PROVIDER_RULES
from secrets_scanner.detect import Config
from secrets_scanner.report import REDACT_PREFIX, fingerprint, redact, to_json, to_sarif, to_text
from secrets_scanner.scanner import scan_paths

from helpers import ROOT, run_cli, tok


def test_redact_shows_short_prefix_and_fingerprint_only():
    v = "abcdefgh" + "Z" * 24
    r = redact(v)
    assert r == f"abcd****[{fingerprint(v)}]" and len(fingerprint(v)) == 12
    assert redact("abcdefg").startswith("a****") and redact("abcdefgh").startswith("ab****")  # prefix never exceeds a quarter of the value
    assert REDACT_PREFIX == 4 and v not in r


def test_raw_value_never_appears_in_any_output_format(tmp_path):
    for seed in range(12):
        rule = PROVIDER_RULES[seed % len(PROVIDER_RULES)]
        t = tok(rule, seed)
        f = tmp_path / f"f{seed}.env"
        f.write_text(f"API_KEY={t}\n")
        res = scan_paths([str(f)], Config())
        assert res.findings
        blob = to_text(res.findings) + json.dumps(to_json(res.findings, {})) + json.dumps(to_sarif(res.findings))
        assert t not in blob and t[8:] not in blob


def test_sarif_2_1_0_structure():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.yml"
        p.write_text(f"token: {tok('github-token', 1)}\n")
        findings = scan_paths([str(p)], Config()).findings
    s = to_sarif(findings)
    assert s["version"] == "2.1.0" and s["$schema"].endswith("sarif-2.1.0.json")
    run = s["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["tool"]["driver"]["name"] == "sec-secrets-scanner" and len(run["results"]) == len(findings) >= 1
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1 and "\\" not in loc["artifactLocation"]["uri"]
        assert re.fullmatch(r"[0-9a-f]{12}", res["partialFingerprints"]["secretFingerprint/v1"])
    j = to_json(findings, {"x": 1})
    assert set(j["findings"][0]) >= {"path", "line", "rule", "score", "redacted", "fingerprint"}


def test_exit_0_on_clean_tree_and_ignored_dirs_are_not_walked(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\nname = 'customer_account_balance'\n")
    assert run_cli("scan", ".", cwd=tmp_path).returncode == 0
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "cfg").write_text(f"TOKEN = '{tok('github-token', 1)}'\n")
    assert run_cli("scan", ".", cwd=tmp_path).returncode == 0


def test_exit_1_on_findings_with_file_line_and_no_raw_value(tmp_path):
    t = tok("github-token", 4)
    (tmp_path / "a.py").write_text(f"x = 1\nTOKEN = '{t}'\n")
    r = run_cli("scan", "a.py", cwd=tmp_path)
    assert r.returncode == 1 and r.stdout.startswith("a.py:2: github-token")
    assert t not in r.stdout + r.stderr


def test_json_and_sarif_output_files_via_cli(tmp_path):
    (tmp_path / "a.py").write_text(f"TOKEN = '{tok('github-token', 4)}'\n")
    assert run_cli("scan", "a.py", "--format", "json", "--output", "o.json", cwd=tmp_path).returncode == 1
    assert json.loads((tmp_path / "o.json").read_text())["summary"]["findings"] == 1
    assert run_cli("scan", "a.py", "--format", "sarif", "--output", "o.sarif", cwd=tmp_path).returncode == 1
    assert json.loads((tmp_path / "o.sarif").read_text())["version"] == "2.1.0"


def test_exit_2_on_missing_path_bad_baseline_and_bad_diff(tmp_path):
    r = run_cli("scan", "nope", cwd=tmp_path)
    assert r.returncode == 2 and "not found" in r.stderr
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.json").write_text("{not json")
    assert run_cli("scan", "a.py", "--baseline", "b.json", cwd=tmp_path).returncode == 2
    assert run_cli("scan", "--diff", "-", stdin="hello world\n", cwd=tmp_path).returncode == 2
    assert run_cli("scan", "--diff", "missing.diff", cwd=tmp_path).returncode == 2


def test_binary_files_are_skipped_not_errors(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + tok("github-token", 1).encode())
    r = run_cli("scan", ".", "--format", "json", cwd=tmp_path)
    assert r.returncode == 0 and json.loads(r.stdout)["summary"]["skipped"] == 1


def _bash():
    for c in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        if c and Path(c).exists():
            return c
    return None


@pytest.mark.skipif(_bash() is None or shutil.which("git") is None, reason="needs bash and git")
def test_pre_commit_hook_blocks_staged_secret_and_allows_clean(tmp_path):
    def git(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    hook = (ROOT / "hooks" / "pre-commit").as_posix()
    env = {**__import__("os").environ, "SECSCAN_PYTHON": sys.executable.replace("\\", "/")}

    def run_hook():
        return subprocess.run([_bash(), hook], cwd=tmp_path, capture_output=True, text=True, env=env, timeout=120)

    (tmp_path / "ok.py").write_text("x = 1\n")
    git("add", "ok.py")
    assert run_hook().returncode == 0
    (tmp_path / "bad.py").write_text(f"TOKEN = '{tok('github-token', 5)}'\n")
    git("add", "bad.py")
    r = run_hook()
    assert r.returncode == 1 and "bad.py:1:" in r.stdout
