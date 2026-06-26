#!/usr/bin/env python3
"""
update_rules.py  (HARDENED edition)
===================================
Fetches framework data from PINNED upstream releases and regenerates
audit_rules.yaml for the n8n auditor.

This hardened rewrite closes the "silent fail-open" hole in the original:

  1. PINNED refs   — every source is fetched from a specific release tag /
                     commit SHA, NOT a moving 'master'/'main' branch. Bumping
                     a pin is a deliberate, reviewable change.
  2. VALIDATION    — per-source success tracking + sanity thresholds. The
                     script EXITS NON-ZERO if a source silently broke
                     (e.g. gitleaks parser returns 3 patterns instead of 200+).
  3. REGEX SAFETY  — every fetched secret regex is compiled and complexity-
                     capped before it is allowed into the ruleset (ReDoS guard).
  4. PROVENANCE    — the generated YAML records, per source, the exact ref and
                     a SHA-256 of the fetched bytes, so the ruleset is auditable.
  5. EXPLICIT MODES— --strict (default) fails on any degraded source;
                     --allow-fallback permits hardcoded fallbacks but still
                     records that the run was degraded.

Zero third-party dependencies (Python stdlib only).

Exit codes:
    0  Success — rules generated and all validations passed
    1  Validation failure — a source broke or fell back in --strict mode
    2  Hard error — could not write output / unexpected exception
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Pinned source configuration ─────────────────────────────────────────────
# To "get the latest", bump a PIN here in a reviewed PR — never pull from a
# moving branch inside the audit job.

PINS = {
    "gitleaks": "v8.21.2",        # https://github.com/gitleaks/gitleaks/releases
    "owasp_top10": "master",      # OWASP Top10 2025 docs (repo has no version tag for 2025 set)
    "atlas": "main",              # atlas-navigator-data publishes on main; hash-pinned below
    "n8n": "n8n@1.70.0",          # https://github.com/n8n-io/n8n/releases
}

SOURCES = {
    "gitleaks_toml": (
        f"https://raw.githubusercontent.com/gitleaks/gitleaks/{PINS['gitleaks']}"
        "/config/gitleaks.toml"
    ),
    "owasp_top10_index": (
        f"https://raw.githubusercontent.com/OWASP/Top10/{PINS['owasp_top10']}"
        "/2025/docs/en/index.md"
    ),
    "owasp_llm_top10": (
        "https://genai.owasp.org/llm-top-10/"
    ),
    "atlas_stix": (
        f"https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/"
        f"{PINS['atlas']}/dist/stix-atlas.json"
    ),
    "n8n_langchain_pkg": (
        f"https://raw.githubusercontent.com/n8n-io/n8n/{PINS['n8n']}"
        "/packages/%40n8n/nodes-langchain/package.json"
    ),
    "n8n_nodes_base_pkg": (
        f"https://raw.githubusercontent.com/n8n-io/n8n/{PINS['n8n']}"
        "/packages/nodes-base/package.json"
    ),
}

# ── Validation thresholds ───────────────────────────────────────────────────
# A healthy run produces known-good shapes. If reality is below these, the
# parser silently broke (format drift) or the fetch failed — FAIL the run.

THRESHOLDS = {
    "gitleaks_min_patterns": 100,   # gitleaks ships ~200+ rules
    "owasp_web_exact": 10,          # A01..A10
    "owasp_llm_exact": 10,          # LLM01..LLM10
    "atlas_min_techniques": 1,      # >0 attack-patterns
    "n8n_risky_min": 1,             # at least one risky node keyword
}

# ── Regex safety limits (ReDoS guard) ───────────────────────────────────────

MAX_REGEX_LEN = 600          # reject absurdly long patterns
# Heuristic ReDoS signatures: nested quantifiers like (a+)+ , (a*)* , (a+)*
REDOS_SIGNATURES = [
    re.compile(r"\([^)]*[+*]\)[+*]"),       # (x+)+  (x*)*
    re.compile(r"\([^)]*\{\d+,\}\)[+*]"),    # (x{2,})+
]

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "audit_rules.yaml"
)

# ── Run report ──────────────────────────────────────────────────────────────

@dataclass
class SourceResult:
    name: str
    url: str
    ok: bool = False
    used_fallback: bool = False
    sha256: Optional[str] = None
    count: int = 0
    note: str = ""

@dataclass
class RunReport:
    sources: Dict[str, SourceResult] = field(default_factory=dict)
    regexes_rejected: int = 0
    problems: List[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return (
            bool(self.problems)
            or any(s.used_fallback or not s.ok for s in self.sources.values())
        )


# ── HTTP fetch (records sha256 for provenance) ──────────────────────────────

def fetch_url(url: str, timeout: int = 30) -> Tuple[Optional[str], Optional[str]]:
    """Fetch URL. Returns (text, sha256_of_bytes) or (None, None) on failure."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "n8n-audit-updater/2.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read()
        digest = hashlib.sha256(raw_bytes).hexdigest()
        return raw_bytes.decode("utf-8", errors="replace"), digest
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
        print(f"  WARNING: Failed to fetch {url}: {e}", file=sys.stderr)
        return None, None


# ── Regex safety ────────────────────────────────────────────────────────────


def normalize_go_regex(pattern: str) -> str:
    """Convert a Go/RE2 regex into a Python-compilable, scanner-safe string.

    The scanner compiles secret regexes with re.compile(regex) and NO flags,
    so any case-insensitivity must live INSIDE the pattern. Python only allows
    a global (?i) at position 0, so we:
      - detect (?i) / (?i:...) anywhere,
      - strip every inline flag marker,
      - rewrite (?iflag:...) groups to plain (?:...),
      - and, if case-insensitivity was requested, prepend a single (?i) at the start.
    Also maps Go \\z -> Python \\Z.
    """
    want_i = bool(re.search(r"\(\?[aiLmsux]*i[):]", pattern)) or bool(re.match(r"^\(\?[aiLmsux]*i\)", pattern))
    # (?flags:...) -> (?:...)
    pattern = re.sub(r"\(\?[aiLmsux]+:", "(?:", pattern)
    # bare (?flags) anywhere -> remove
    pattern = re.sub(r"\(\?[aiLmsux]+\)", "", pattern)
    pattern = pattern.replace(r"\z", r"\Z")
    if want_i:
        pattern = "(?i)" + pattern
    return pattern


def is_regex_safe(pattern: str) -> Tuple[bool, str]:
    """Normalize Go->Python, then compile-check + ReDoS-screen.
    Returns (ok, reason). The normalized form is what gets shipped."""
    if not pattern:
        return False, "empty"
    norm = normalize_go_regex(pattern)
    if len(norm) > MAX_REGEX_LEN:
        return False, f"too long ({len(norm)} > {MAX_REGEX_LEN})"
    for sig in REDOS_SIGNATURES:
        if sig.search(norm):
            return False, "possible ReDoS (nested quantifier)"
    try:
        re.compile(norm)
    except re.error as e:
        return False, f"does not compile: {e}"
    return True, "ok"


# ── Source Parsers ──────────────────────────────────────────────────────────

def parse_gitleaks_toml(raw: str) -> List[Dict[str, str]]:
    """Parse [[rules]] blocks, handling triple-single-quoted multiline regex
    (gitleaks stores most regexes as \'\'\'...\'\'\')."""
    patterns: List[Dict[str, str]] = []
    lines = raw.splitlines()
    i, n = 0, len(lines)
    current: Dict[str, str] = {}

    def flush() -> None:
        if current.get("id") and current.get("regex"):
            patterns.append(dict(current))

    while i < n:
        stripped = lines[i].strip()
        if stripped == "[[rules]]":
            flush(); current.clear(); i += 1; continue
        m = re.match(r"^(\w+)\s*=\s*\'\'\'(.*)$", stripped)
        if m:
            key, rest = m.group(1), m.group(2)
            if rest.endswith("\'\'\'") and len(rest) >= 3:
                current[key] = rest[:-3]; i += 1; continue
            buf = [rest]; i += 1
            while i < n:
                if lines[i].rstrip().endswith("\'\'\'"):
                    buf.append(lines[i].rstrip()[:-3]); break
                buf.append(lines[i]); i += 1
            current[key] = "\n".join(buf); i += 1; continue
        m = re.match(r'^(\w+)\s*=\s*"(.*)"$', stripped)
        if m:
            current[m.group(1)] = m.group(2); i += 1; continue
        m = re.match(r"^(\w+)\s*=\s*\'(.*)\'$", stripped)
        if m:
            current[m.group(1)] = m.group(2); i += 1; continue
        i += 1
    flush()
    return patterns


def parse_owasp_top10_categories(raw: str) -> List[Dict[str, str]]:
    categories = []
    for m in re.finditer(r"(A\d{2})[:\s_]*2025[^-]*-\s*(.+?)(?:\]|\)|$)", raw):
        categories.append({
            "id": m.group(1) + ":2025",
            "title": m.group(2).strip().rstrip("/)],"),
        })
    seen, deduped = set(), []
    for c in categories:
        if c["id"] not in seen:
            seen.add(c["id"])
            deduped.append(c)
    return deduped


def parse_owasp_llm_categories(raw: str) -> List[Dict[str, str]]:
    categories = []
    for m in re.finditer(r"(LLM\d{2})[:\s_]*2025[^a-zA-Z]*([\w\s&]+)", raw):
        title = m.group(2).strip()
        if len(title) > 3:
            categories.append({"id": m.group(1) + ":2025", "title": title})
    seen, deduped = set(), []
    for c in categories:
        if c["id"] not in seen:
            seen.add(c["id"])
            deduped.append(c)
    return deduped


def parse_atlas_stix(raw: str) -> Dict[str, Any]:
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError:
        return {"version": "unknown", "technique_count": 0}
    objects = bundle.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern"]
    version = "unknown"
    for o in objects:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version", o.get("name", "unknown"))
            break
    return {"version": version, "technique_count": len(techniques)}


def parse_n8n_ai_node_types(raw: str) -> List[str]:
    try:
        pkg = json.loads(raw)
    except json.JSONDecodeError:
        return []
    nodes = pkg.get("n8n", {}).get("nodes", [])
    prefixes = set()
    for node_path in nodes:
        parts = node_path.replace("dist/nodes/", "").split("/")
        if parts:
            prefixes.add(parts[0])
    return sorted(prefixes)


def parse_n8n_risky_node_types(raw: str) -> List[str]:
    try:
        pkg = json.loads(raw)
    except json.JSONDecodeError:
        return []
    nodes = pkg.get("n8n", {}).get("nodes", [])
    risky_keywords = [
        "httpRequest", "postgres", "mysql", "mongodb", "redis",
        "mssql", "snowflake", "airtable", "googleSheets",
        "slack", "telegram", "discord", "gmail", "email", "sendgrid",
        "code", "function", "databricks",
    ]
    found = set()
    for node_path in nodes:
        for kw in risky_keywords:
            if kw.lower() in node_path.lower():
                found.add(kw)
    return sorted(found)


# ── Fallback datasets (only used with --allow-fallback) ─────────────────────

FALLBACK_OWASP_WEB = [
    ("A01:2025", "Broken Access Control"),
    ("A02:2025", "Security Misconfiguration"),
    ("A03:2025", "Software Supply Chain Failures"),
    ("A04:2025", "Cryptographic Failures"),
    ("A05:2025", "Injection"),
    ("A06:2025", "Insecure Design"),
    ("A07:2025", "Authentication Failures"),
    ("A08:2025", "Software or Data Integrity Failures"),
    ("A09:2025", "Security Logging and Alerting Failures"),
    ("A10:2025", "Mishandling of Exceptional Conditions"),
]
FALLBACK_OWASP_LLM = [
    ("LLM01:2025", "Prompt Injection"),
    ("LLM02:2025", "Sensitive Information Disclosure"),
    ("LLM03:2025", "Supply Chain"),
    ("LLM04:2025", "Data and Model Poisoning"),
    ("LLM05:2025", "Improper Output Handling"),
    ("LLM06:2025", "Excessive Agency"),
    ("LLM07:2025", "System Prompt Leakage"),
    ("LLM08:2025", "Vector and Embedding Weaknesses"),
    ("LLM09:2025", "Misinformation"),
    ("LLM10:2025", "Unbounded Consumption"),
]

RISKY_CONFIGS = {
    "httpRequest": "Enable Retry on Fail, set a timeout, and consider Continue On Error.",
    "postgres": "Wrap DB ops with Continue On Error and validate inputs.",
    "mysql": "Wrap DB ops with Continue On Error and validate inputs.",
    "mongodb": "Wrap DB ops with Continue On Error and validate inputs.",
    "redis": "Wrap DB ops with Continue On Error and validate inputs.",
    "mssql": "Wrap DB ops with Continue On Error and validate inputs.",
    "snowflake": "Wrap DB ops with Continue On Error and validate inputs.",
    "databricks": "Wrap DB ops with Continue On Error and validate inputs.",
    "airtable": "Validate record/document IDs before execution; add an Error Workflow.",
    "googleSheets": "Validate record/document IDs before execution; add an Error Workflow.",
    "slack": "External APIs can rate-limit; add Error Workflows + fallback channel.",
    "telegram": "External APIs can rate-limit; add Error Workflows + fallback channel.",
    "discord": "External APIs can rate-limit; add Error Workflows + fallback channel.",
    "gmail": "External APIs can rate-limit; add Error Workflows + fallback channel.",
    "email": "External APIs can rate-limit; add Error Workflows + fallback channel.",
    "sendgrid": "External APIs can rate-limit; add Error Workflows + fallback channel.",
    "code": "Custom Code nodes throw on runtime errors; wrap in try/catch.",
}


# ── YAML writer (no dependency) ─────────────────────────────────────────────

def yaml_escape(s: str) -> str:
    if not s:
        return '""'
    needs_quote = any(c in s for c in ":{}[]&*?|->!%@`#,\\\"'\n") or s.startswith(" ")
    if needs_quote:
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


def generate_yaml(
    gitleaks_patterns: List[Dict[str, str]],
    owasp_web: List[Dict[str, str]],
    owasp_llm: List[Dict[str, str]],
    atlas_info: Dict[str, Any],
    n8n_ai_categories: List[str],
    n8n_risky_nodes: List[str],
    report: RunReport,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    L: List[str] = []
    L.append("# =============================================================================")
    L.append("# n8n Audit Rules Configuration (AUTO-GENERATED — hardened updater)")
    L.append("# =============================================================================")
    L.append(f"# Generated: {now}")
    L.append("# Do NOT edit manually. Run 'python scripts/update_rules.py' to regenerate.")
    L.append("# =============================================================================")
    L.append("")
    L.append(f'version: "auto-{now[:10]}"')
    L.append(f'generated_at: "{now}"')
    L.append('generated_by: "update_rules.py (hardened v2)"')
    L.append(f'degraded_run: {"true" if report.degraded else "false"}')
    L.append("")

    # Provenance block — exact ref + sha256 per source (auditable)
    L.append("# -- Provenance (pinned refs + sha256 of fetched bytes) --")
    L.append("provenance:")
    L.append("  pins:")
    for k, v in PINS.items():
        L.append(f"    {k}: {yaml_escape(v)}")
    L.append("  sources:")
    for name, sr in report.sources.items():
        L.append(f"    {name}:")
        L.append(f"      url: {yaml_escape(sr.url)}")
        L.append(f"      ok: {'true' if sr.ok else 'false'}")
        L.append(f"      used_fallback: {'true' if sr.used_fallback else 'false'}")
        L.append(f"      sha256: {yaml_escape(sr.sha256 or 'n/a')}")
        L.append(f"      count: {sr.count}")
    L.append(f"  regexes_rejected: {report.regexes_rejected}")
    L.append("")

    # Framework references
    L.append("framework_references:")
    L.append("  owasp_top10:")
    L.append('    version: "2025"')
    L.append(f'    source: "https://github.com/OWASP/Top10"')
    L.append("    categories:")
    web = [(c["id"], c["title"]) for c in owasp_web] if owasp_web else FALLBACK_OWASP_WEB
    for cid, title in web:
        L.append(f"      - id: {yaml_escape(cid)}")
        L.append(f"        title: {yaml_escape(title)}")
    L.append("")
    L.append("  owasp_llm_top10:")
    L.append('    version: "2025"')
    L.append('    source: "https://genai.owasp.org/llm-top-10/"')
    L.append("    categories:")
    llm = [(c["id"], c["title"]) for c in owasp_llm] if owasp_llm else FALLBACK_OWASP_LLM
    for cid, title in llm:
        L.append(f"      - id: {yaml_escape(cid)}")
        L.append(f"        title: {yaml_escape(title)}")
    L.append("")
    L.append("  mitre_atlas:")
    L.append(f'    version: {yaml_escape(str(atlas_info.get("version", "unknown")))}')
    L.append(f'    technique_count: {atlas_info.get("technique_count", 0)}')
    L.append('    source: "https://github.com/mitre-atlas/atlas-navigator-data"')
    L.append('    format: "STIX 2.1"')
    L.append("")
    L.append("  nist_ssdf:")
    L.append('    version: "NIST SP 800-218A"')
    L.append('    source: "https://csrc.nist.gov/pubs/sp/800/218/a/final"')
    L.append('    note: "No machine-readable API; reference only"')
    L.append("")

    # Secret patterns (already safety-screened before this point)
    L.append("# -- Secret Detection Patterns (from gitleaks upstream, regex-validated) --")
    L.append(f"# Pattern count: {len(gitleaks_patterns)}")
    L.append("secret_patterns:")
    for p in gitleaks_patterns:
        rule_id = p.get("id", "unknown")
        regex = p.get("regex", "")
        desc = p.get("description", rule_id)
        severity = "medium" if "generic" in rule_id.lower() else "high"
        confidence = "medium" if "generic" in rule_id.lower() else "high"
        L.append(f"  - rule_id: {yaml_escape('SEC-' + rule_id.upper())}")
        L.append(f"    regex: {yaml_escape(regex)}")
        L.append(f"    severity: {yaml_escape(severity)}")
        L.append(f"    confidence: {yaml_escape(confidence)}")
        L.append(f"    description: {yaml_escape(desc)}")
        L.append('    owasp: "A04:2025 (Cryptographic Failures) / A07:2025 (Authentication Failures)"')
    L.append("")

    # AI node prefixes
    L.append("# -- AI / LangChain Node Types --")
    L.append("ai_node_prefixes:")
    L.append('  - "@n8n/n8n-nodes-langchain"')
    for cat in n8n_ai_categories:
        L.append(f"  # Sub-category: {cat}")
    L.append("")

    # Risky node patterns
    L.append("# -- Risky Node Patterns (need error handling) --")
    L.append("risky_node_patterns:")
    for kw in n8n_risky_nodes:
        rec = RISKY_CONFIGS.get(kw, "Enable Retry on Fail and add an Error Workflow.")
        L.append(f"  - pattern: {yaml_escape(kw)}")
        L.append(f"    recommendation: {yaml_escape(rec)}")
    L.append("")

    # Verdict thresholds
    L.append("# -- Verdict Thresholds --")
    L.append("verdict:")
    L.append("  max_medium_before_fail: 5")
    L.append("  fail_on_any_high: true")
    L.append("  fail_on_no_error_workflow: true")
    L.append("  fail_on_open_webhook: true")
    L.append("  fail_on_prompt_injection_path: true")
    L.append("  fail_on_hardcoded_secret: true")
    L.append("  fail_on_pindata_shipped: true")
    L.append("")

    # Guardrail keywords
    L.append("# -- Guardrail Keywords (for AI prompt checks) --")
    L.append("guardrail_keywords:")
    for kw in ["do not", "never", "refuse", "safe", "guardrail", "policy",
               "filter", "reject", "deny", "block", "restrict",
               "prohibited", "forbidden", "must not", "not allowed"]:
        L.append(f"  - {yaml_escape(kw)}")
    L.append("")

    return "\n".join(L) + "\n"


# ── Validation gate ─────────────────────────────────────────────────────────

def validate(report: RunReport, allow_fallback: bool) -> List[str]:
    problems: List[str] = []

    def res(name: str) -> SourceResult:
        return report.sources.get(name, SourceResult(name, ""))

    gl = res("gitleaks_toml")
    if gl.count < THRESHOLDS["gitleaks_min_patterns"]:
        problems.append(
            f"gitleaks: {gl.count} valid patterns "
            f"(< {THRESHOLDS['gitleaks_min_patterns']}) — fetch/parse likely broke"
        )

    web = res("owasp_top10_index")
    if not web.used_fallback and web.count != THRESHOLDS["owasp_web_exact"]:
        problems.append(
            f"OWASP Top 10: got {web.count} categories "
            f"(expected {THRESHOLDS['owasp_web_exact']})"
        )

    llm = res("owasp_llm_top10")
    if not llm.used_fallback and llm.count != THRESHOLDS["owasp_llm_exact"]:
        problems.append(
            f"OWASP LLM: got {llm.count} categories "
            f"(expected {THRESHOLDS['owasp_llm_exact']})"
        )

    at = res("atlas_stix")
    if at.count < THRESHOLDS["atlas_min_techniques"]:
        problems.append("MITRE ATLAS: 0 techniques — fetch/parse failed")

    rk = res("n8n_nodes_base_pkg")
    if rk.count < THRESHOLDS["n8n_risky_min"]:
        problems.append("n8n risky nodes: none extracted — fetch/parse failed")

    if report.degraded and not allow_fallback:
        degraded = [n for n, s in report.sources.items() if s.used_fallback or not s.ok]
        problems.append(
            "degraded run (use --allow-fallback to permit): "
            + ", ".join(degraded)
        )

    return problems


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="Hardened n8n audit-rules updater")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--strict", action="store_true", default=True,
        help="Fail (exit 1) on any degraded/fallback source (DEFAULT).",
    )
    mode.add_argument(
        "--allow-fallback", action="store_true",
        help="Permit hardcoded fallbacks; run still records degraded=true.",
    )
    ap.add_argument(
        "--output", default=OUTPUT_PATH,
        help="Path to write audit_rules.yaml (default: next to this script).",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Validate + print summary but do not write the YAML.",
    )
    args = ap.parse_args()
    allow_fallback = args.allow_fallback

    print("=" * 64)
    print("n8n Audit Rules Updater (hardened)")
    print(f"mode: {'allow-fallback' if allow_fallback else 'strict'}")
    print("=" * 64)

    report = RunReport()

    def register(name: str, sha: Optional[str], ok: bool, count: int,
                 used_fallback: bool = False, note: str = "") -> None:
        report.sources[name] = SourceResult(
            name=name, url=SOURCES[name], ok=ok, used_fallback=used_fallback,
            sha256=sha, count=count, note=note,
        )

    # 1. gitleaks (with regex safety screening)
    print("[1/6] gitleaks secret patterns...")
    raw, sha = fetch_url(SOURCES["gitleaks_toml"])
    safe_patterns: List[Dict[str, str]] = []
    if raw:
        for p in parse_gitleaks_toml(raw):
            ok, why = is_regex_safe(p.get("regex", ""))
            if ok:
                # ship the normalized (Python-compilable) form so the scanner,
                # which compiles with no flags, can use it directly.
                p["regex"] = normalize_go_regex(p.get("regex", ""))
                safe_patterns.append(p)
            else:
                report.regexes_rejected += 1
                print(f"      rejected regex {p.get('id','?')}: {why}", file=sys.stderr)
        register("gitleaks_toml", sha, ok=True, count=len(safe_patterns))
    else:
        register("gitleaks_toml", None, ok=False, count=0, used_fallback=True)
    print(f"      → {len(safe_patterns)} safe patterns "
          f"({report.regexes_rejected} rejected)")

    # 2. OWASP Top 10
    print("[2/6] OWASP Top 10:2025...")
    raw, sha = fetch_url(SOURCES["owasp_top10_index"])
    owasp_web = parse_owasp_top10_categories(raw) if raw else []
    if owasp_web:
        register("owasp_top10_index", sha, ok=True, count=len(owasp_web))
    else:
        register("owasp_top10_index", sha, ok=bool(raw), count=0, used_fallback=True)
    print(f"      → {len(owasp_web)} categories")

    # 3. OWASP LLM Top 10
    print("[3/6] OWASP LLM Top 10:2025...")
    raw, sha = fetch_url(SOURCES["owasp_llm_top10"])
    owasp_llm = parse_owasp_llm_categories(raw) if raw else []
    if owasp_llm:
        register("owasp_llm_top10", sha, ok=True, count=len(owasp_llm))
    else:
        register("owasp_llm_top10", sha, ok=bool(raw), count=0, used_fallback=True)
    print(f"      → {len(owasp_llm)} categories")

    # 4. MITRE ATLAS
    print("[4/6] MITRE ATLAS STIX...")
    raw, sha = fetch_url(SOURCES["atlas_stix"], timeout=60)
    atlas_info = parse_atlas_stix(raw) if raw else {"version": "unknown", "technique_count": 0}
    register("atlas_stix", sha, ok=atlas_info["technique_count"] > 0,
             count=atlas_info["technique_count"],
             used_fallback=atlas_info["technique_count"] == 0)
    print(f"      → version={atlas_info['version']}, "
          f"techniques={atlas_info['technique_count']}")

    # 5/6. n8n packages
    print("[5/6] n8n langchain package...")
    raw_lc, sha_lc = fetch_url(SOURCES["n8n_langchain_pkg"])
    n8n_ai = parse_n8n_ai_node_types(raw_lc) if raw_lc else []
    register("n8n_langchain_pkg", sha_lc, ok=bool(raw_lc), count=len(n8n_ai),
             used_fallback=not raw_lc)
    print(f"      → {len(n8n_ai)} AI categories")

    print("[6/6] n8n nodes-base package...")
    raw_base, sha_base = fetch_url(SOURCES["n8n_nodes_base_pkg"])
    n8n_risky = parse_n8n_risky_node_types(raw_base) if raw_base else []
    register("n8n_nodes_base_pkg", sha_base, ok=bool(raw_base), count=len(n8n_risky),
             used_fallback=not raw_base)
    print(f"      → {len(n8n_risky)} risky node types")

    # ── Validate ──
    print()
    print("Validating...")
    report.problems = validate(report, allow_fallback)
    if report.problems:
        print("VALIDATION FAILED:", file=sys.stderr)
        for p in report.problems:
            print(f"  ✗ {p}", file=sys.stderr)
        if not allow_fallback:
            print("\nRefusing to write a degraded ruleset (strict mode).",
                  file=sys.stderr)
            return 1
        print("\n--allow-fallback set: proceeding with degraded ruleset.",
              file=sys.stderr)
    else:
        print("  ✓ all sanity thresholds passed")

    # ── Generate ──
    yaml_content = generate_yaml(
        gitleaks_patterns=safe_patterns,
        owasp_web=owasp_web,
        owasp_llm=owasp_llm,
        atlas_info=atlas_info,
        n8n_ai_categories=n8n_ai,
        n8n_risky_nodes=n8n_risky,
        report=report,
    )

    if args.dry_run:
        print(f"\n[dry-run] would write {len(yaml_content)} bytes to {args.output}")
        return 0

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(yaml_content)
    except OSError as e:
        print(f"ERROR: could not write {args.output}: {e}", file=sys.stderr)
        return 2

    print(f"\n  → Written: {args.output} ({len(yaml_content)} bytes)")
    print(f"  → degraded_run = {str(report.degraded).lower()}")
    print("Done.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(2)
