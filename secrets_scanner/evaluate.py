"""Precision/recall on the seeded corpus, dev/held-out split, threshold tuning (dev only), demo table."""
import itertools
import random
from dataclasses import replace
from functools import lru_cache

from .corpus import build_corpus
from .detect import MODES, Config, scan_lines

GRID = {"min_len": (16, 20, 24), "ent_hex": (2.8, 3.0, 3.2, 3.4), "ent_b64": (3.2, 3.5, 3.8, 4.1),
        "ctx": (0.4, 0.5, 0.6, 0.7)}
TUNED_FIELDS = {"patterns": (), "entropy": ("min_len", "ent_hex", "ent_b64"),
                "context": ("min_len", "ent_hex", "ent_b64", "ctx"), "combined": ("min_len", "ent_hex", "ent_b64", "ctx")}


def split_cases(cases, seed: int = 7):
    """Stratified by category, seeded shuffle, alternate dev / held-out."""
    by = {}
    for c in cases:
        by.setdefault(c.category, []).append(c)
    dev, held = [], []
    rng = random.Random(seed)
    for cat in sorted(by):
        items = by[cat][:]
        rng.shuffle(items)
        dev += items[0::2]
        held += items[1::2]
    return dev, held


def flagged(case, cfg) -> bool:
    return bool(scan_lines(enumerate(case.text.splitlines(), 1), cfg))


def evaluate(cases, cfg: Config) -> dict:
    tp = fp = fn = tn = 0
    by_cat = {}
    for c in cases:
        f = flagged(c, cfg)
        k, n = by_cat.get(c.category, (0, 0))
        by_cat[c.category] = (k + f, n + 1)
        if c.label:
            tp, fn = tp + f, fn + (not f)
        else:
            fp, tn = fp + f, tn + (not f)
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r,
            "f1": 2 * p * r / (p + r) if p + r else 0.0, "by_cat": by_cat}


def tune(dev, mode: str) -> Config:
    """Grid search on the DEV cases only. Ties: higher F1, then fewer false positives, then grid order."""
    fields = TUNED_FIELDS[mode]
    best, best_key = Config(mode=mode), None
    for vals in itertools.product(*(GRID[f] for f in fields)):
        cfg = replace(Config(mode=mode), **dict(zip(fields, vals)))
        m = evaluate(dev, cfg)
        key = (m["f1"], -m["fp"])
        if best_key is None or key > best_key:
            best, best_key = cfg, key
    return best


@lru_cache(maxsize=None)
def run_all(seed: int = 1337, split_seed: int = 7):
    dev, held = split_cases(build_corpus(seed), split_seed)
    out = {}
    for mode in MODES:
        cfg = tune(dev, mode)
        out[mode] = {"cfg": cfg, "dev": evaluate(dev, cfg), "held": evaluate(held, cfg)}
    return {"dev_n": len(dev), "held_n": len(held), "modes": out, "held_cases": held}


def demo() -> str:
    r = run_all()
    lines = [f"Seeded corpus (seed 1337): {r['dev_n']} dev cases, {r['held_n']} held-out cases. "
             "Thresholds tuned on dev only; metrics below are case-level.", "",
             f"{'layer':<10} {'devF1':>6} | {'prec':>5} {'recall':>6} {'F1':>5} | {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} | tuned params (held-out)"]
    for mode in MODES:
        e = r["modes"][mode]
        h, c = e["held"], e["cfg"]
        params = ", ".join(f"{f}={getattr(c, f)}" for f in TUNED_FIELDS[mode]) or "none"
        lines.append(f"{mode:<10} {e['dev']['f1']:>6.3f} | {h['precision']:>5.3f} {h['recall']:>6.3f} {h['f1']:>5.3f} | "
                     f"{h['tp']:>3} {h['fp']:>3} {h['fn']:>3} {h['tn']:>3} | {params}")
    lines += ["", "Held-out per category: positives = detected/total, negatives = falsely flagged/total",
              f"{'category':<20} {'kind':<4} " + " ".join(f"{m:>9}" for m in MODES)]
    held = r["held_cases"]
    kinds = {c.category: c.label for c in held}
    for cat in sorted(kinds, key=lambda c: (not kinds[c], c)):
        cells = []
        for mode in MODES:
            k, n = r["modes"][mode]["held"]["by_cat"][cat]
            cells.append(f"{k}/{n}")
        lines.append(f"{cat:<20} {'pos' if kinds[cat] else 'neg':<4} " + " ".join(f"{x:>9}" for x in cells))
    comb = r["modes"]["combined"]["held"]["by_cat"]
    miss = [f"{c} ({comb[c][0]}/{comb[c][1]})" for c in kinds if kinds[c] and comb[c][0] < comb[c][1]]
    fps = [f"{c} ({comb[c][0]}/{comb[c][1]})" for c in kinds if not kinds[c] and comb[c][0] > 0]
    lines += ["", "Still missed (combined, held-out): " + (", ".join(miss) or "none"),
              "Still falsely flagged (combined, held-out): " + (", ".join(fps) or "none")]
    return "\n".join(lines)
