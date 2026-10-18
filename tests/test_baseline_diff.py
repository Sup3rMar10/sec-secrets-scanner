import datetime as dt
import json

import pytest

from secrets_scanner.baseline import BaselineError, apply_baseline, load_baseline
from secrets_scanner.detect import Config
from secrets_scanner.diffparse import DiffError, parse_diff
from secrets_scanner.scanner import scan_diff, scan_paths

from helpers import run_cli, scan_text, tok

PW = "Qw3rTy9uIoPz" * 2


def _entry(fp, **kw):
    d = {"fingerprint": fp, "reason": "fixture", "expires": "2026-12-31"}
    d.update(kw)
    return d


def _baseline_file(tmp_path, entries):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"entries": entries}))
    return str(p)


def _finding(tmp_path):
    f = tmp_path / "a.env"
    f.write_text(f"SECRET_TOKEN={tok('github-token', 1)}\n")
    return scan_paths([str(f)], Config()).findings[0]


def make_diff():
    secret = tok("github-token", 9)
    return "\n".join([
        "diff --git a/app.py b/app.py", "index 111..222 100644", "--- a/app.py", "+++ b/app.py",
        "@@ -10,3 +10,4 @@", " import os", f"-OLD = '{secret}'", "+clean = 1", f'+TOKEN = "{secret}"', " print(1)",
        "diff --git a/cfg.yml b/cfg.yml", "--- /dev/null", "+++ b/cfg.yml", "@@ -0,0 +1,2 @@", "+a: 1",
        f'+password: "{PW}"',
        "diff --git a/old.txt b/old.txt", "--- a/old.txt", "+++ /dev/null", "@@ -1,1 +0,0 @@",
        f"-leaked = '{secret}'", "\\ No newline at end of file", ""]), secret


def test_nosecret_with_reason_suppresses():
    t = tok("github-token", 2)
    assert scan_text(f"k = '{t}'")
    assert not scan_text(f"k = '{t}'  # nosecret: parser fixture, not a credential")


def test_nosecret_without_reason_is_rejected_not_honoured():
    t = tok("github-token", 2)
    for suffix in ("# nosecret", "# nosecret:   ", "// nosecret:"):
        hits = scan_text(f"k = '{t}'  {suffix}")
        assert hits and all(m.rejected for _, m in hits), suffix


def test_baseline_suppresses_by_fingerprint_and_unrelated_entry_does_not(tmp_path):
    f = _finding(tmp_path)
    ok = load_baseline(_baseline_file(tmp_path, [_entry(f.fingerprint)]))
    assert apply_baseline([f], ok, dt.date(2026, 6, 1))[1] == 1
    other = load_baseline(_baseline_file(tmp_path, [_entry("0" * 12)]))
    assert apply_baseline([f], other, dt.date(2026, 6, 1))[1] == 0


def test_baseline_expiry_boundary_is_inclusive(tmp_path):
    f = _finding(tmp_path)
    entries = load_baseline(_baseline_file(tmp_path, [_entry(f.fingerprint, expires="2026-12-31")]))
    kept, n, expired = apply_baseline([f], entries, dt.date(2026, 12, 31))
    assert (kept, n, expired) == ([], 1, [])
    kept, n, expired = apply_baseline([f], entries, dt.date(2027, 1, 1))
    assert kept == [f] and n == 0 and len(expired) == 1


def test_baseline_validation_rejects_bad_entries(tmp_path):
    bad = [_entry("0" * 12, reason=""), _entry("0" * 12, reason="   "), _entry("0" * 12, expires="31/12/2026"),
           _entry("xyz"), {"fingerprint": "0" * 12, "expires": "2026-12-31"}]
    for e in bad:
        with pytest.raises(BaselineError):
            load_baseline(_baseline_file(tmp_path, [e]))
    (tmp_path / "n.json").write_text('{"entries": 5}')
    with pytest.raises(BaselineError):
        load_baseline(str(tmp_path / "n.json"))


def test_baseline_path_glob_scopes_the_entry(tmp_path):
    f = _finding(tmp_path)
    miss = load_baseline(_baseline_file(tmp_path, [_entry(f.fingerprint, path="other/*")]))
    assert apply_baseline([f], miss, dt.date(2026, 6, 1))[1] == 0
    hit = load_baseline(_baseline_file(tmp_path, [_entry(f.fingerprint, path="*.env")]))
    assert apply_baseline([f], hit, dt.date(2026, 6, 1))[1] == 1


def test_write_baseline_roundtrip_and_expiry_via_cli(tmp_path):
    (tmp_path / "a.env").write_text(f"SECRET_TOKEN={tok('github-token', 1)}\n")
    assert run_cli("scan", "a.env", "--write-baseline", "b.json", "--expires", "2026-12-31", cwd=tmp_path).returncode == 0
    assert run_cli("scan", "a.env", "--baseline", "b.json", "--today", "2026-12-31", cwd=tmp_path).returncode == 0
    late = run_cli("scan", "a.env", "--baseline", "b.json", "--today", "2027-01-01", cwd=tmp_path)
    assert late.returncode == 1 and "baseline entry expired" in late.stdout


def test_parse_diff_returns_only_added_lines_with_new_numbers():
    diff, secret = make_diff()
    got = parse_diff(diff)
    assert got["app.py"] == [(11, "clean = 1"), (12, f'TOKEN = "{secret}"')]
    assert got["cfg.yml"][1] == (2, f'password: "{PW}"')
    assert "old.txt" not in got  # deleted file: nothing added
    res = scan_diff(diff, Config())  # the removed copy of the secret (and the deleted file) are never reported
    assert sorted((f.path, f.line) for f in res.findings) == [("app.py", 12), ("cfg.yml", 2)]


def test_added_line_that_looks_like_file_header_is_content():
    diff = "--- a/n.txt\n+++ b/n.txt\n@@ -0,0 +1,2 @@\n+++ not a header\n+k = 1\n\\ No newline at end of file\n"
    assert parse_diff(diff) == {"n.txt": [(1, "++ not a header"), (2, "k = 1")]}


def test_garbage_diff_raises():
    with pytest.raises(DiffError):
        parse_diff("this is not a diff\nat all\n")
    assert parse_diff("") == {}


def test_cli_diff_from_stdin_reports_file_line_without_raw_value():
    diff, secret = make_diff()
    r = run_cli("scan", "--diff", "-", stdin=diff)
    assert r.returncode == 1
    assert "app.py:12:" in r.stdout and "cfg.yml:2:" in r.stdout
    assert secret not in r.stdout + r.stderr and PW not in r.stdout + r.stderr
