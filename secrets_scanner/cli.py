"""CLI. Exit codes: 0 clean, 1 findings, 2 could not scan (bad path, bad baseline, bad diff, unreadable file)."""
import argparse
import datetime as dt
import json
import sys

from .baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from .detect import MODES, Config
from .diffparse import DiffError
from .patterns import RULES
from .report import to_json, to_sarif, to_text
from .scanner import scan_diff, scan_paths


def build_parser():
    p = argparse.ArgumentParser(prog="secrets_scanner", description="Secrets scanner for source trees and git diffs")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan paths, or only the added lines of a diff")
    s.add_argument("paths", nargs="*")
    s.add_argument("--diff", metavar="FILE", help="unified diff to scan ('-' = stdin); only ADDED lines are scanned")
    s.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("--output", metavar="FILE")
    s.add_argument("--baseline", metavar="FILE")
    s.add_argument("--write-baseline", metavar="FILE", help="write current findings as baseline entries, exit 0")
    s.add_argument("--expires", metavar="YYYY-MM-DD", help="expiry for --write-baseline (default today+90d)")
    s.add_argument("--reason", default="initial baseline; triage required")
    s.add_argument("--today", metavar="YYYY-MM-DD", help=argparse.SUPPRESS)
    d = Config()
    s.add_argument("--mode", choices=MODES, default=d.mode)
    s.add_argument("--min-len", type=int, default=d.min_len)
    s.add_argument("--ent-hex", type=float, default=d.ent_hex)
    s.add_argument("--ent-b64", type=float, default=d.ent_b64)
    s.add_argument("--ctx", type=float, default=d.ctx)
    sub.add_parser("demo", help="print the measured precision/recall table")
    sub.add_parser("rules", help="list provider patterns")
    return p


def _scan(args) -> int:
    cfg = Config(args.mode, args.min_len, args.ent_hex, args.ent_b64, args.ctx)
    try:
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
        expires = dt.date.fromisoformat(args.expires) if args.expires else today + dt.timedelta(days=90)
        entries = load_baseline(args.baseline) if args.baseline else []
        if args.diff:
            raw = sys.stdin.buffer.read() if args.diff == "-" else open(args.diff, "rb").read()
            res = scan_diff(raw.decode("utf-8", "replace"), cfg)
        else:
            res = scan_paths(args.paths or ["."], cfg)
    except (DiffError, BaselineError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    res.findings, res.suppressed, res.expired = apply_baseline(res.findings, entries, today)
    expired_fps = {e.fingerprint for e in res.expired}
    for f in res.findings:
        f.baseline_expired = f.fingerprint in expired_fps
    for e in res.errors:
        print(f"error: {e}", file=sys.stderr)
    if args.write_baseline:
        write_baseline(res.findings, args.write_baseline, expires, args.reason)
        print(f"wrote {len(res.findings)} baseline entries to {args.write_baseline} (expire {expires})", file=sys.stderr)
        return 2 if res.errors else 0
    summary = {"mode": cfg.mode, "files_scanned": res.files_scanned, "findings": len(res.findings),
               "suppressed_by_baseline": res.suppressed, "skipped": len(res.skipped), "errors": len(res.errors)}
    if args.format == "json":
        out = json.dumps(to_json(res.findings, summary), indent=2)
    elif args.format == "sarif":
        out = json.dumps(to_sarif(res.findings), indent=2)
    else:
        out = to_text(res.findings)
        print(f"summary: {summary}", file=sys.stderr)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out + "\n")
    elif out:
        print(out)
    return 2 if res.errors else (1 if res.findings else 0)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "demo":
        from .evaluate import demo
        print(demo())
        return 0
    if args.cmd == "rules":
        for r in RULES:
            print(f"{r.id:<20} {r.desc}")
        return 0
    return _scan(args)
