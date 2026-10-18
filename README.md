# sec-secrets-scanner

![ci](https://github.com/Sup3rMar10/sec-secrets-scanner/actions/workflows/ci.yml/badge.svg)

A **stdlib-only secrets scanner** for source trees and git diffs. Three detection layers (provider-style token patterns, per-character-class Shannon entropy, and context scoring), a `scan --diff` mode that looks only at **added** lines, an expiring baseline, reason-required inline suppressions, JSON and SARIF 2.1.0 output, a pre-commit hook, and **no raw secret ever printed** (short prefix plus hash fingerprint only).

> **What is verified, and what is not.** 45 tests pass locally on Python 3.13 (stdlib only; pytest for the tests). CI has not run yet, so no CI claim is made. I broke 9 behaviours on purpose (entropy and length boundaries, diff added-line handling, redaction, baseline expiry, the reason-required rule, the exit code, the placeholder penalty, split-string joining) and the tests failed each time (9 of 9 killed). **The data is synthetic.** Every fake credential is assembled at runtime from fragments plus a seeded random body and exists only in memory or in temp dirs; the committed repo contains none (a test scans the repo with this scanner). The corpus and the scanner were written by the same person in the same sitting, so the numbers below are **optimistic**: they show the layers behave as designed on known hard cases, not what you would see on a real codebase. There is no real-repo recall or false-positive-rate measurement here.

## Measured results

Seeded corpus (seed 1337, 26 categories x 12 cases = 312 cases; 14 positive and 12 negative categories, one of them plain code), split stratified into 156 dev and 156 held-out. Thresholds are grid-searched **on dev only** (per layer); the table is **held-out**, case-level (a case counts as flagged if the scanner reports at least one finding in it).

| layer | dev F1 | precision | recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| patterns only | 0.372 | 0.759 | 0.262 | 0.389 | 22 | 7 | 62 | 65 |
| entropy only (no filters, no context) | 0.706 | 0.578 | 0.929 | 0.712 | 78 | 57 | 6 | 15 |
| entropy + filters + context | 0.776 | 0.792 | 0.726 | 0.758 | 61 | 16 | 23 | 56 |
| **combined** (shipped default) | 0.846 | **0.917** | 0.786 | **0.846** | 66 | 6 | 18 | 66 |

What each layer contributes (held-out, from `python -m secrets_scanner demo`):
- **Patterns** are precise on their shapes and catch URL credentials (6/6) that entropy misses (the password is short), but find 0 of the named YAML/JSON/env secrets.
- **Entropy alone** catches almost everything and flags almost every hard negative (git SHAs, UUIDs, base64 images, lockfile integrity strings, minified JS, long identifiers: 6/6 each).
- **Context + shape filters** remove those false positives; the combined layer adds patterns back for provider tokens that have no telling variable name.
- Default thresholds (min length 16, hex entropy 2.8, base64 entropy 3.2, context score 0.6) are the dev optimum. They are loose; a real tree with lots of random-looking data will need re-tuning.

## What it still misses (held-out, combined)
- **Unnamed secrets** (`value = "<random>"`): 0/6. Without a telling name, context cannot lift the score; lowering the threshold costs precision.
- **Passphrases made of dictionary words** (`password = "four-plain-words"`): 0/6, because the identifier filter treats them as names.
- **High-entropy secrets embedded in minified JS**: 0/6 (entropy is skipped on minified lines; provider patterns still apply).
- **False positives:** hex strings under a secret-like name that are really references (`release_token_ref: <40 hex>`): 6/6 flagged. A hex API key and a hex commit reference look the same.

## Run
```
python -m secrets_scanner scan .                              # text; exit 0 clean, 1 findings, 2 could not scan
python -m secrets_scanner scan . --format sarif --output out.sarif
python -m secrets_scanner scan . --baseline .secretscan-baseline.json
git diff --cached -U0 | python -m secrets_scanner scan --diff -   # added lines only, file:line
python -m secrets_scanner demo                                # the measured table above
python -m secrets_scanner rules                               # provider patterns
python -m pytest                                              # 45 tests
```
- Baseline entry: `{"fingerprint": "<12 hex>", "reason": "...", "expires": "YYYY-MM-DD", "path": "optional glob"}`. Reason and date are required; an entry suppresses through its expiry date inclusive, then the finding returns (marked "baseline entry expired"). `scan PATH --write-baseline FILE` drafts one.
- Inline: `# nosecret: reason` suppresses that line. A bare `# nosecret` is **not** honoured and the finding is marked as such.
- Hook: copy `hooks/pre-commit` to `.git/hooks/pre-commit` (set `SECSCAN_HOME` if the scanner lives elsewhere).

## Layout
```
secrets_scanner/  patterns.py (8 documented rules)  entropy.py (Shannon, classes, shape filters)
                  detect.py (layers, context score, nosecret)  diffparse.py  baseline.py  report.py (redact, JSON, SARIF)
                  scanner.py (tree + diff)  corpus.py (seeded generator, no full tokens)  evaluate.py (split, tune, demo)  cli.py
hooks/pre-commit  tests/ (45 tests)  .secretscan-baseline.json (empty: the repo self-scans clean)
```

## Known gaps
- Corpus authored alongside the scanner; no independent or real-repo benchmark. The shape filters were written knowing the hard negatives.
- Provider patterns are a small generic set (8), not a maintained provider list. No card-number, personal-data or cloud-specific verification (live-key checks) by design.
- Fingerprints are an unsalted truncated SHA-256: a very weak secret could be guessed offline from its fingerprint.
- Split-string joining handles `"a" + "b"` on one line only; not multi-line, `join()`, f-strings or runtime construction. Base64 unwrapping is one level, standard alphabet, ASCII only.
- A placeholder word such as "test" or "example" on the line lowers the score by design, so a real secret on such a line can be missed.
- Files over 1 MB and binary files are skipped (counted in the summary, not an error). Not a replacement for history scanning or push protection.
- GitHub Actions has not run on this repo yet.
