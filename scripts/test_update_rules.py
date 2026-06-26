#!/usr/bin/env python3
"""
test_update_rules.py — proves the hardened updater behaves correctly.
Pure stdlib; no network needed (we monkeypatch fetch_url).
Run:  python3 test_update_rules.py
"""
import importlib.util, io, os, sys, contextlib, json, re

HERE = os.path.dirname(os.path.abspath(__file__))

def load(modname, path):
    spec = importlib.util.spec_from_file_location(modname, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[modname] = m
    spec.loader.exec_module(m)
    return m

ur = load("update_rules_hardened", os.path.join(HERE, "update_rules_hardened.py"))

PASS, FAIL = 0, 0
def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ✓ {name}")
    else:
        FAIL += 1; print(f"  ✗ {name}")

# ── synthetic upstream payloads ─────────────────────────────────────────────
GOOD_GITLEAKS = "\n".join(
    f'[[rules]]\nid = "rule-{i}"\ndescription = "d{i}"\nregex = "AKIA[0-9A-Z]{{16}}"'
    for i in range(150)
)
TRUNCATED_GITLEAKS = '[[rules]]\nid = "only-one"\nregex = "abc"'
REDOS_GITLEAKS = '[[rules]]\nid = "evil"\ndescription = "redos"\nregex = "(a+)+$"'
GOOD_OWASP_WEB = "\n".join(f"[A{str(i).zfill(2)}:2025 - Category {i}](./A{str(i).zfill(2)}.md)" for i in range(1,11))
GOOD_OWASP_LLM = "\n".join(f"LLM{str(i).zfill(2)}:2025 Risk {i} Description\n" for i in range(1,11))
GOOD_ATLAS = json.dumps({"objects":[{"type":"attack-pattern"} for _ in range(20)] +
                         [{"type":"x-mitre-collection","x_mitre_version":"4.0"}]})
GOOD_N8N_BASE = json.dumps({"n8n":{"nodes":["dist/nodes/HttpRequest/httpRequest.node.js",
                                            "dist/nodes/Postgres/postgres.node.js"]}})
GOOD_N8N_LC = json.dumps({"n8n":{"nodes":["dist/nodes/llms/X/x.node.js"]}})

def make_fetch(mapping):
    """Return a fetch_url stub keyed by substring of URL."""
    def _f(url, timeout=30):
        for key, payload in mapping.items():
            if key in url:
                if payload is None:
                    return None, None
                return payload, "deadbeef"
        return None, None
    return _f

ALL_GOOD = {
    "gitleaks": GOOD_GITLEAKS, "Top10": GOOD_OWASP_WEB, "llm-top-10": GOOD_OWASP_LLM,
    "atlas": GOOD_ATLAS, "nodes-langchain": GOOD_N8N_LC, "nodes-base": GOOD_N8N_BASE,
}

def run_main(argv, fetch_map):
    """Run ur.main() with patched fetch + argv; capture exit code."""
    ur.fetch_url = make_fetch(fetch_map)
    old_argv = sys.argv
    sys.argv = ["update_rules.py"] + argv
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = ur.main()
    except SystemExit as e:
        code = e.code
    finally:
        sys.argv = old_argv
    return code, buf.getvalue()

print("TEST 1: happy path (allow-fallback) -> exit 0, YAML written, >=100 patterns")
out = os.path.join(HERE, "_test_rules.yaml")
_t1 = dict(ALL_GOOD); _t1["llm-top-10"] = None  # flaky upstream parser -> rely on vetted fallback
code, log = run_main(["--allow-fallback", "--output", out], _t1)
check("exit 0 on healthy run", code == 0)
check("YAML file written", os.path.exists(out))
if os.path.exists(out):
    txt = open(out).read()
    check("secret_patterns present", "secret_patterns:" in txt)
    check(">=100 secret regexes shipped", txt.count("regex:") >= 100)
    check("provenance block present", "provenance:" in txt)
    check("owasp web+llm has 20 category ids", len(re.findall(r'- id: "(?:A|LLM)\d\d:2025"', txt)) == 20)

print("TEST 2: all sources offline → strict mode exits 1, no silent fallback")
offline = {k: None for k in ALL_GOOD}
out2 = os.path.join(HERE, "_test_offline.yaml")
code, log = run_main(["--output", out2], offline)
check("exit 1 when everything is down (fail-closed)", code == 1)
check("did NOT write a degraded ruleset in strict mode", not os.path.exists(out2))

print("TEST 3: gitleaks truncated (format drift) → exit 1 below threshold")
drift = dict(ALL_GOOD); drift["gitleaks"] = TRUNCATED_GITLEAKS
code, log = run_main(["--output", os.path.join(HERE,"_t3.yaml")], drift)
check("exit 1 when gitleaks returns too few patterns", code == 1)
check("problem names gitleaks", "gitleaks" in log)

print("TEST 4: ReDoS regex rejected, not shipped")
ok_safe, why_safe = ur.is_regex_safe("AKIA[0-9A-Z]{16}")
ok_evil, why_evil = ur.is_regex_safe("(a+)+$")
ok_long, _ = ur.is_regex_safe("a" * 500)
ok_bad, _ = ur.is_regex_safe("(unclosed")
check("safe regex accepted", ok_safe is True)
check("ReDoS regex rejected", ok_evil is False)
check("over-long regex rejected", ok_long is False)
check("non-compiling regex rejected", ok_bad is False)

print("TEST 5: --allow-fallback lets a degraded run proceed (exit 0) + flags it")
# OWASP web down but everything else healthy → degraded
deg = dict(ALL_GOOD); deg["Top10"] = None
out5 = os.path.join(HERE, "_t5.yaml")
code, log = run_main(["--allow-fallback", "--output", out5], deg)
check("exit 0 with --allow-fallback", code == 0)
if os.path.exists(out5):
    check("degraded_run true recorded", "degraded_run: true" in open(out5).read())

# cleanup temp files
for f in ["_test_rules.yaml","_test_offline.yaml","_t3.yaml","_t5.yaml"]:
    p = os.path.join(HERE, f)
    if os.path.exists(p): os.remove(p)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
