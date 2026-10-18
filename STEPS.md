# STEPS

**Part A** is what I did, in order. **Part B** is how you run it.

---

## Part A: steps taken

1. **Set the fixture rule first:** no complete credential-shaped token may ever be written to the repo or a commit. All fake secrets are built in code from fragments (`"gh" + "p_"` style) plus a seeded random body, and only exist in memory or temp dirs. Decision: a test scans the repo with the scanner itself.
2. **Wrote the pattern layer:** 8 small generic rules (prefix plus fixed-length body, JWT shape, PEM header, `scheme://user:pass@host`).
3. **Wrote the entropy layer:** Shannon entropy per character class (hex vs base64-ish), a length threshold, both inclusive, plus shape filters for known benign things (UUID, lockfile integrity, data URIs, snake/camel identifiers, minified lines).
4. **Wrote context scoring:** base score, plus a sensitive name (`password`, `token`, `api_key`...), plus config shape, minus placeholder words (`example`, `test`...), minus hash words (`sha`, `commit`...), looking at the line and the previous line. Split strings (`"a" + "b"`) are joined and one level of base64 is unwrapped.
5. **Wrote the plumbing:** unified-diff parser that tracks hunk counts (so an added line starting with `++ ` is not a header), baseline with mandatory reason and expiry, reason-required `nosecret`, redaction (quarter-of-value prefix capped at 4 plus a 12-hex fingerprint), JSON and SARIF 2.1.0, exit codes 0/1/2, pre-commit hook.
6. **Built the seeded corpus** (26 categories x 12 cases, hard positives and hard negatives) and the evaluation: stratified dev/held-out split, grid search on dev only, per-layer table. After the first run came out too clean I added three categories I knew the scanner would struggle with (passphrases, secrets inside minified JS, hex references under secret-like names) so the report shows real misses.
7. **Wrote 45 tests**, including seeded property tests, exact-threshold boundary tests, real-subprocess exit-code tests, and a hook test through Git Bash.
8. **Mutation-checked 9 behaviours** on a fresh copy each time; 9 of 9 killed.
9. **Wrote README and this file**, then committed locally (no push).

Problems and choices along the way:
- The self-scan found a real hit on the first run: the description string of the URL-credentials rule contained a literal `user:password@host`. Reworded to `user:<secret>@host`.
- A seeded test caught a real regex bug: Google-style and Slack-style tokens whose body ends in `-` were missed because the trailing `\b` needs a word character. Replaced by a negative lookahead.
- Two of my own tests were wrong (an all-digit "hex" boundary token is classed as digits; a git-SHA generator built a new `Random(5)` per character), fixed on the first failing run.
- Tuned defaults (min length 16, thresholds 2.8 / 3.2 / 0.6) are loose and a test keeps `Config()` equal to the dev optimum, so changing the corpus forces a conscious update.

---

## Part B: steps for you

### Run it
1. Needs Python 3.11 or newer. No packages (pytest only for the tests).
2. `python -m secrets_scanner demo` prints the measured table (a few seconds).
3. `python -m secrets_scanner scan <path>`; exit code 0 clean, 1 findings, 2 could not scan.
4. Diff mode: `git diff --cached -U0 | python -m secrets_scanner scan --diff -`.

### Run the tests
`python -m pytest` (45 tests, about 20 seconds; the hook test is skipped if bash or git is missing).

### Install the hook
`cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit` (set `SECSCAN_HOME` to this checkout if the repo being committed is a different one).

### Baseline
`python -m secrets_scanner scan . --write-baseline .secretscan-baseline.json --expires 2027-01-31`, then edit each `reason`.
