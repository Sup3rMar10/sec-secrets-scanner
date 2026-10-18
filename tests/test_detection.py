import math
import random

from secrets_scanner.corpus import NEGATIVES, PROVIDER_RULES, b64
from secrets_scanner.detect import Config, context_score
from secrets_scanner.entropy import char_class, passes, shannon

from helpers import scan_text, tok


def test_shannon_known_values():
    assert shannon("01234567" * 3) == 3.0
    assert shannon("") == 0.0 and shannon("aaaaaaaa") == 0.0


def test_entropy_threshold_is_inclusive():
    t = "0123abcd" * 3  # hex class, 24 chars, entropy exactly 3.0
    assert passes(t, Config(ent_hex=3.0, min_len=20))
    assert not passes(t, Config(ent_hex=3.01, min_len=20))


def test_min_len_boundary_is_inclusive():
    t = "aB3dE5gH7jK9mN1pQ3sT"
    assert len(t) == 20
    assert passes(t, Config(min_len=20, ent_b64=0.0))
    assert not passes(t[:19], Config(min_len=20, ent_b64=0.0))


def test_char_class():
    assert char_class("deadbeef12") == "hex"
    assert char_class("1234567890") == "digits"
    assert char_class("deadbeefzz") == "b64"


def test_entropy_permutation_invariant_and_bounded():
    for seed in range(40):
        rng = random.Random(seed)
        s = "".join(rng.choice("abcXYZ019+/") for _ in range(rng.randint(1, 60)))
        shuffled = list(s)
        rng.shuffle(shuffled)
        assert abs(shannon(s) - shannon("".join(shuffled))) < 1e-9
        assert -1e-9 <= shannon(s) <= math.log2(len(s)) + 1e-9


def test_every_provider_pattern_matches_in_patterns_mode():
    for rule in PROVIDER_RULES + ("private-key-header", "url-credentials"):
        hits = scan_text(f"x = '{tok(rule, 3)}'", mode="patterns")
        assert [m.rule for _, m in hits] == [rule], rule


def test_pattern_body_length_boundary():
    for rule in ("aws-access-key-id", "github-token", "google-api-key"):
        t = tok(rule, 1)
        assert scan_text(f"x = {t}", mode="patterns")
        assert not scan_text(f"x = {t[:-1]}", mode="patterns"), rule + " one short"
        assert not scan_text(f"x = {t}A", mode="patterns"), rule + " one long"


def test_url_credentials_flagged_template_ignored():
    assert scan_text("u = " + tok("url-credentials", 2))
    assert not scan_text("u = postgres://app:${DB_PASSWORD}@db:5432/app")


def test_sensitive_name_and_shape_raise_context_score():
    def score(line):
        s = line.index("ABCDEFGH")
        return context_score(line, "", s, s + 8, 0.0)

    assert abs(score('api_key = "ABCDEFGH"') - score('value = "ABCDEFGH"') - 0.5) < 1e-9
    assert abs(score('value = "ABCDEFGH"') - score('value ABCDEFGH') - 0.1) < 1e-9  # config shape bonus


def test_placeholder_word_suppresses_pattern_hit_in_combined_only():
    line = f"# example: export TOKEN={tok('github-token', 4)}"
    assert scan_text(line, mode="patterns")
    assert not scan_text(line, mode="combined")


def test_hard_negative_shapes_not_flagged_by_default_config():
    for cat in ("uuid", "data_image", "lockfile", "minified_js", "long_identifier", "hash_digest", "git_sha",
                "plain_code", "url_template", "named_hash", "example_token"):
        for seed in range(10):
            text = NEGATIVES[cat](random.Random(seed))
            assert not scan_text(text), (cat, seed)


def test_git_sha_flagged_by_entropy_only_but_not_combined():
    rng = random.Random(5)
    line = "commit " + "".join(rng.choice("0123456789abcdef") for _ in range(40))
    assert scan_text(line, mode="entropy", ent_hex=3.0)
    assert not scan_text(line, mode="combined")


def test_split_string_is_joined_before_matching():
    t = tok("github-token", 6)
    line = f'cfg = "{t[:7]}" + "{t[7:19]}" + "{t[19:]}"'
    hits = scan_text(line, mode="patterns")
    assert [m.rule for _, m in hits] == ["github-token"]


def test_base64_wrapped_secret_assignment_detected():
    line = 'payload = "%s"' % b64("password=" + "Zk3" * 6)
    assert [m.rule for _, m in scan_text(line)] == ["base64-wrapped"]
    assert not scan_text(line, mode="patterns")


def test_secret_in_comment_detected():
    hits = scan_text('# old key, rotate later: api_key = "' + "Qw3rTy9uIo" * 2 + '"')
    assert hits and hits[0][1].rule == "high-entropy-string"


def test_minified_line_skips_entropy_but_patterns_still_apply():
    filler = "function a(b,c){return b+1};" * 25
    line = f'var h="{"Qw3rTy9uIoPz" * 3}";{filler}'
    assert not scan_text(line)
    assert scan_text(line + f'var t="{tok("github-token", 7)}";')


def test_previous_line_context_lowers_score():
    value = "Qw3rTy9uIoPz" * 2
    assert scan_text(f'password: "{value}"')
    assert not scan_text(f"# placeholder values below\npassword: \"{value}\"")
