import re

from secrets_scanner.corpus import POSITIVES, NEGATIVES, build_corpus
from secrets_scanner.detect import Config
from secrets_scanner.evaluate import evaluate, run_all, split_cases, tune

from helpers import ROOT, run_cli


def test_corpus_is_deterministic_per_seed_and_balanced():
    a, b, c = build_corpus(1), build_corpus(1), build_corpus(2)
    assert a == b and a != c
    assert len(a) == 12 * (len(POSITIVES) + len(NEGATIVES))
    assert sum(x.label for x in a) == 12 * len(POSITIVES)


def test_split_is_disjoint_stratified_and_deterministic():
    cases = build_corpus(3)
    dev, held = split_cases(cases, 7)
    assert not {c.id for c in dev} & {c.id for c in held} and len(dev) + len(held) == len(cases)
    assert {c.category for c in dev} == {c.category for c in held}
    assert (dev, held) == split_cases(cases, 7) and dev != split_cases(cases, 8)[0]


def test_tuning_uses_dev_only_and_beats_or_ties_default_on_dev():
    dev, held = split_cases(build_corpus(1337), 7)
    cfg = tune(dev, "combined")
    assert cfg == tune(dev, "combined")
    assert evaluate(dev, cfg)["f1"] >= evaluate(dev, Config())["f1"]
    assert not {c.id for c in dev} & {c.id for c in held}  # tune() is only ever handed the dev cases


def test_shipped_defaults_equal_dev_tuned_combined():
    assert run_all()["modes"]["combined"]["cfg"] == Config()


def test_combined_beats_each_single_layer_on_held_out():
    m = run_all()["modes"]
    f1 = {k: v["held"]["f1"] for k, v in m.items()}
    assert f1["combined"] > f1["patterns"] and f1["combined"] > f1["entropy"] and f1["combined"] >= f1["context"]
    assert m["combined"]["held"]["precision"] > m["entropy"]["held"]["precision"]
    assert m["patterns"]["held"]["recall"] < 0.5 < m["entropy"]["held"]["recall"]


def test_known_misses_are_reported_not_hidden():
    by = run_all()["modes"]["combined"]["held"]["by_cat"]
    assert by["generic_name"][0] == 0 and by["passphrase"][0] == 0 and by["minified_embedded"][0] == 0
    assert by["named_hex_ref"][0] > 0  # documented false-positive class


def test_demo_prints_table_via_real_subprocess():
    r = run_cli("demo")
    assert r.returncode == 0 and "combined" in r.stdout and "Still missed" in r.stdout


def test_repo_self_scan_has_no_findings_beyond_allowlist():
    """The repo (generator, tests, docs) must contain no credential-shaped literal."""
    r = run_cli("scan", ".", "--baseline", ".secretscan-baseline.json", "--format", "json")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not re.search(r'"findings": \[\s*\{', r.stdout)
