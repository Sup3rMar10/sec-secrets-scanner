"""Seeded labelled corpus. Every credential-shaped token is ASSEMBLED AT RUNTIME from fragments plus a
seeded random body; this file contains no complete token. Cases live in memory (or temp dirs in tests)."""
import base64
import random
import string
from dataclasses import dataclass

ALNUM = string.ascii_letters + string.digits
UPPER_DIG = string.ascii_uppercase + string.digits
B64 = ALNUM + "+/"
URLSAFE = ALNUM + "_-"
HEX = "0123456789abcdef"

FRAGS = {
    "aws-access-key-id": ("AK", "IA"),
    "github-token": ("gh", "p_"),
    "slack-token": ("xo", "xb-"),
    "stripe-live-key": ("sk", "_live_"),
    "google-api-key": ("AI", "za"),
    "jwt": ("ey", "J"),
    "private-key-header": ("-----BEGIN ", "RSA ", "PRIVATE KEY-----"),
}
PROVIDER_RULES = ("aws-access-key-id", "github-token", "slack-token", "stripe-live-key", "google-api-key", "jwt")
WORDS = ("customer", "account", "balance", "process", "records", "payment", "order", "handler", "factory",
         "singleton", "abstract", "region", "invoice", "report", "manager", "service", "queue", "worker")
NOISE = ("region: us-east-1", "retries = 3", "import os", "def main():", "debug: false", "x = compute(1, 2)", "")


def body(rng, n, alphabet=ALNUM):
    return "".join(rng.choice(alphabet) for _ in range(n))


def make_token(rule, rng):
    f = "".join(FRAGS.get(rule, ()))
    if rule == "aws-access-key-id":
        return f + body(rng, 16, UPPER_DIG)
    if rule == "github-token":
        return f + body(rng, 36)
    if rule == "slack-token":
        return f + body(rng, 24)
    if rule == "stripe-live-key":
        return f + body(rng, 24)
    if rule == "google-api-key":
        return f + body(rng, 35, URLSAFE)
    if rule == "jwt":
        return f + body(rng, 14, URLSAFE) + "." + f + body(rng, 14, URLSAFE) + "." + body(rng, 22, URLSAFE)
    if rule == "private-key-header":
        return f
    if rule == "url-credentials":
        return "post" + "gres://svc:" + body(rng, 14) + "@db.internal:5432/app"
    raise ValueError(rule)


def b64(s):
    return base64.b64encode(s.encode()).decode()


# ---- hard positives -------------------------------------------------------------------------
def pos_provider_code(r):
    return f'{r.choice(["client", "svc", "session"])} = Service(key="{make_token(r.choice(PROVIDER_RULES), r)}")'


def pos_provider_yaml(r):
    return f"credentials:\n  value: {make_token(r.choice(PROVIDER_RULES), r)}\n  region: us-east-1"


def pos_yaml_named(r):
    return f'database:\n  host: db.internal\n  password: "{body(r, r.randint(20, 28))}"'


def pos_json_named(r):
    return '{"api_key": "%s", "region": "us-east-1"}' % body(r, 32, B64)


def pos_env_named(r):
    return f"APP_ENV=prod\nSECRET_TOKEN={body(r, 32)}"


def pos_url_creds(r):
    return "DATABASE_URL=" + make_token("url-credentials", r)


def pos_split_string(r):
    if r.random() < 0.5:
        tok = make_token("github-token", r)
        a, b = sorted(r.sample(range(2, len(tok) - 2), 2))
        return "cfg = " + " + ".join(f'"{p}"' for p in (tok[:a], tok[a:b], tok[b:]))
    v = body(r, 28)
    return f'password = "{v[:14]}" + "{v[14:]}"'


def pos_b64_wrapped(r):
    if r.random() < 0.5:
        return f'payload = "{b64("password=" + body(r, 16))}"'
    return f"blob: {b64(make_token('github-token', r))}"


def pos_comment_secret(r):
    return f'x = 1\n# old key, rotate later: api_key = "{body(r, 24)}"'


def pos_named_hex(r):
    return f"secret_key: {body(r, 32, HEX)}"


def pos_generic_name(r):
    return f'value = "{body(r, 32)}"'


def pos_auth_header(r):
    return f"Authorization: Bearer {body(r, 40)}"


# ---- hard negatives -------------------------------------------------------------------------
def _uuid(r):
    return "-".join(body(r, n, HEX) for n in (8, 4, 4, 4, 12))


def neg_git_sha(r):
    h = body(r, 40, HEX)
    return r.choice([f"commit {h}\nAuthor: Dev One <dev@corp.invalid>", f"git checkout {h}", f"ref = {h}", f"sha: {h}"])


def neg_uuid(r):
    u = _uuid(r)
    return r.choice([f'"id": "{u}"', f"request_id = '{u}'", f"correlation-id: {u}"])


def neg_hash_digest(r):
    return r.choice([f"md5: {body(r, 32, HEX)}", f'etag: "{body(r, 32, HEX)}"',
                     f"image: registry.local/app@sha256:{body(r, 64, HEX)}"])


def neg_data_image(r):
    return f'<img alt="logo" src="data:image/png;base64,{body(r, r.randint(200, 400), B64)}" />'


def neg_minified_js(r):
    v = lambda: r.choice(string.ascii_lowercase) + r.choice(["", str(r.randint(0, 9))])  # noqa: E731
    s = f'var h="{body(r, 40, HEX)}";var d="{body(r, 48, B64)}";'
    while len(s) < 700:
        s += f"function {v()}({v()},{v()}){{return {v()}+{r.randint(1, 99)}}};"
    return s


def neg_lockfile(r):
    return f'    "node_modules/{r.choice(WORDS)}": {{\n      "integrity": "sha512-{body(r, 86, B64)}==",'


def neg_long_identifier(r):
    w = [r.choice(WORDS) for _ in range(r.randint(3, 5))]
    ident = r.choice(["_".join(w), "".join(x.capitalize() for x in w), "-".join(w), "_".join(w).upper()])
    return f"result = {ident}(order)" if r.random() < 0.5 else f"class {ident}:"


def neg_example_token(r):
    t = make_token(r.choice(PROVIDER_RULES), r)
    return r.choice([f"# example: export TOKEN={t}", f"token = '{t}'  # test fixture", f"# sample config\napi_key: {t}"])


def neg_url_template(r):
    return r.choice(["postgres://app:${DB_PASSWORD}@db:5432/app", "redis://cache:{{ redis_secret }}@cache.internal:6379",
                     "https://deploy@" + r.choice(WORDS) + ".internal/repo.git"])


def neg_named_hash(r):
    return r.choice([f'password_hash: "{body(r, 64, HEX)}"', f"secret_sha256 = '{body(r, 64, HEX)}'"])


def neg_plain_code(r):
    return r.choice(['password = prompt("Enter password")', "token = os.environ[\"API_TOKEN\"]",
                     "# the token is rotated every 30 days, see the runbook", "total = sum(x * 2 for x in items)",
                     "secret_manager = SecretManager(region=REGION)"])


def pos_passphrase(r):
    return f'password = "{"-".join(r.sample(WORDS, 4))}"'


def pos_minified_embedded(r):
    s = f'var apiKey="{body(r, 32)}";'
    while len(s) < 700:
        s += f"function {r.choice(string.ascii_lowercase)}(a,b){{return a+{r.randint(1, 99)}}};"
    return s


def neg_named_hex_ref(r):
    return f"release_token_ref: {body(r, 40, HEX)}"


POSITIVES = {k[4:]: v for k, v in list(globals().items()) if k.startswith("pos_")}
NEGATIVES = {k[4:]: v for k, v in list(globals().items()) if k.startswith("neg_")}


@dataclass(frozen=True)
class Case:
    id: str
    label: bool
    category: str
    text: str


def build_corpus(seed: int = 1337, per_cat: int = 12):
    rng = random.Random(seed)
    cases = []
    for label, table in ((True, POSITIVES), (False, NEGATIVES)):
        for cat, fn in table.items():
            for i in range(per_cat):
                pre = [n for n in (rng.choice(NOISE) for _ in range(rng.randint(0, 2))) if n]
                text = "\n".join(pre + [fn(rng)]) + "\n"
                cases.append(Case(f"{cat}-{i:02d}", label, cat, text))
    return cases
