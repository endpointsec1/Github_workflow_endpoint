#!/usr/bin/env python3
"""
update_rules.py
===============
Fetches the latest framework data from upstream sources and regenerates
audit_rules.yaml before the n8n audit script runs.

Upstream sources:
  1. Gitleaks (GitHub)     → secret detection regex patterns
  2. OWASP Top 10 (GitHub) → web app security category IDs
  3. OWASP LLM Top 10      → LLM-specific risk category IDs
  4. MITRE ATLAS (GitHub)   → AI adversary technique IDs (STIX 2.1)
  5. n8n (GitHub)           → AI/LangChain node type prefixes

Zero external dependencies — uses only Python stdlib.
===============

Pipeline execution order:
┌─────────────────────────────────────────────────────────────┐
│  Step A: Run update_rules.py                                │
│          ├── Fetch gitleaks.toml → extract secret patterns  │
│          ├── Fetch OWASP/Top10 repo → extract A01–A10       │
│          ├── Fetch OWASP LLM Top 10 → extract LLM01–LLM10   │
│          ├── Fetch ATLAS STIX JSON → extract technique IDs  │
│          ├── Fetch n8n package.json → extract AI node types │
│          └── Write updated audit_rules.yaml                 │
│                                                             │
│  Step B: Run n8n_audit_v3.py (uses the fresh rules)         │
└─────────────────────────────────────────────────────────────┘


"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ── Configuration ──────────────────────────────────────────────────────────

SOURCES = {
    "gitleaks_toml": (
        "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
    ),
    "owasp_top10_index": (
        "https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/index.md"
    ),
    "owasp_llm_top10": (
        # The OWASP GenAI project page lists all LLM01-LLM10 categories
        "https://genai.owasp.org/llm-top-10/"
    ),
    "atlas_stix": (
        "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/"
        "main/dist/stix-atlas.json"
    ),
    "n8n_langchain_pkg": (
        "https://raw.githubusercontent.com/n8n-io/n8n/master/"
        "packages/%40n8n/nodes-langchain/package.json"
    ),
    "n8n_nodes_base_pkg": (
        "https://raw.githubusercontent.com/n8n-io/n8n/master/"
        "packages/nodes-base/package.json"
    ),
}

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_rules.yaml")


# ── HTTP Fetch Helper ──────────────────────────────────────────────────────

def fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch a URL and return its text content, or None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "n8n-audit-updater/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        print(f"  WARNING: Failed to fetch {url}: {e}", file=sys.stderr)
        return None


# ── Source Parsers ─────────────────────────────────────────────────────────

def parse_gitleaks_toml(raw: str) -> List[Dict[str, str]]:
    """
    Extract rule definitions from gitleaks.toml.
    Each [[rules]] block has: id, description, regex, keywords, etc.
    We parse TOML manually (no 3rd-party dep) since the structure is simple.
    """
    patterns = []
    current: Dict[str, str] = {}

    for line in raw.splitlines():
        stripped = line.strip()

        if stripped == "[[rules]]":
            if current.get("id") and current.get("regex"):
                patterns.append(current)
            current = {}
            continue

        m = re.match(r'^(\w+)\s*=\s*"(.*)"$', stripped)
        if m:
            key, val = m.group(1), m.group(2)
            current[key] = val
        # Also handle triple-quoted or single-quoted
        m2 = re.match(r"^(\w+)\s*=\s*'(.*)'$", stripped)
        if m2:
            key, val = m2.group(1), m2.group(2)
            current[key] = val

    # Capture last block
    if current.get("id") and current.get("regex"):
        patterns.append(current)

    return patterns


def parse_owasp_top10_categories(raw: str) -> List[Dict[str, str]]:
    """Extract A01–A10 category IDs and titles from the OWASP Top 10 index page."""
    categories = []
    # Match patterns like: A01:2025 - Broken Access Control
    for m in re.finditer(r"(A\d{2})[:\s_]*2025[^-]*-\s*(.+?)(?:\]|\)|$)", raw):
        categories.append({
            "id": m.group(1) + ":2025",
            "title": m.group(2).strip().rstrip("/)],"),
        })

    # Deduplicate by ID
    seen = set()
    deduped = []
    for c in categories:
        if c["id"] not in seen:
            seen.add(c["id"])
            deduped.append(c)
    return deduped


def parse_owasp_llm_categories(raw: str) -> List[Dict[str, str]]:
    """Extract LLM01–LLM10 category IDs and titles from OWASP GenAI page."""
    categories = []
    for m in re.finditer(r"(LLM\d{2})[:\s_]*2025[^a-zA-Z]*([\w\s&]+)", raw):
        title = m.group(2).strip()
        if len(title) > 3:
            categories.append({
                "id": m.group(1) + ":2025",
                "title": title,
            })

    seen = set()
    deduped = []
    for c in categories:
        if c["id"] not in seen:
            seen.add(c["id"])
            deduped.append(c)
    return deduped


def parse_atlas_stix(raw: str) -> Dict[str, Any]:
    """Extract ATLAS version and technique count from STIX 2.1 JSON bundle."""
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError:
        return {"version": "unknown", "technique_count": 0}

    objects = bundle.get("objects", [])
    techniques = [
        o for o in objects
        if o.get("type") == "attack-pattern"
    ]
    # Try to find version from the identity or x-mitre-collection object
    version = "unknown"
    for o in objects:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version", o.get("name", "unknown"))
            break

    return {
        "version": version,
        "technique_count": len(techniques),
    }


def parse_n8n_ai_node_types(raw: str) -> List[str]:
    """Extract AI/LangChain node type prefixes from n8n package.json."""
    try:
        pkg = json.loads(raw)
    except json.JSONDecodeError:
        return []

    nodes = pkg.get("n8n", {}).get("nodes", [])
    # Extract the node type prefix patterns
    prefixes = set()
    for node_path in nodes:
        # e.g. "dist/nodes/agents/Agent/Agent.node.js"
        # or "dist/nodes/llms/LMChatOpenAi/LmChatOpenAi.node.js"
        parts = node_path.replace("dist/nodes/", "").split("/")
        if parts:
            prefixes.add(parts[0])  # e.g. "agents", "llms", "mcp", etc.

    return sorted(prefixes)


def parse_n8n_risky_node_types(raw: str) -> List[str]:
    """Extract node type names that are risky (HTTP, DB, etc.) from nodes-base."""
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


# ── YAML Writer (no dependency) ────────────────────────────────────────────

def yaml_escape(s: str) -> str:
    """Escape a string for safe YAML output."""
    if not s:
        return '""'
    # If the string contains special YAML chars, quote it
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
) -> str:
    """Generate the audit_rules.yaml content from parsed upstream data."""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = []
    lines.append("# =============================================================================")
    lines.append("# n8n Audit Rules Configuration (AUTO-GENERATED)")
    lines.append("# =============================================================================")
    lines.append(f"# Generated: {now}")
    lines.append("# Do NOT edit manually. Run 'python scripts/update_rules.py' to regenerate.")
    lines.append("# =============================================================================")
    lines.append("")
    lines.append(f'version: "auto-{now[:10]}"')
    lines.append(f'generated_at: "{now}"')
    lines.append('generated_by: "update_rules.py"')
    lines.append("")

    # ── Framework References ──
    lines.append("# -- Framework References (fetched from upstream) --")
    lines.append("framework_references:")

    lines.append("  owasp_top10:")
    lines.append('    version: "2025"')
    lines.append('    source: "https://github.com/OWASP/Top10"')
    lines.append("    categories:")
    if owasp_web:
        for cat in owasp_web:
            lines.append(f"      - id: {yaml_escape(cat['id'])}")
            lines.append(f"        title: {yaml_escape(cat['title'])}")
    else:
        # Hardcoded fallback (OWASP Top 10:2025 released Nov 2025)
        fallback = [
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
        for cid, title in fallback:
            lines.append(f"      - id: {yaml_escape(cid)}")
            lines.append(f"        title: {yaml_escape(title)}")
        lines.append("    # NOTE: Using hardcoded fallback — upstream fetch failed")

    lines.append("")
    lines.append("  owasp_llm_top10:")
    lines.append('    version: "2025"')
    lines.append('    source: "https://genai.owasp.org/llm-top-10/"')
    lines.append("    categories:")
    if owasp_llm:
        for cat in owasp_llm:
            lines.append(f"      - id: {yaml_escape(cat['id'])}")
            lines.append(f"        title: {yaml_escape(cat['title'])}")
    else:
        fallback_llm = [
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
        for cid, title in fallback_llm:
            lines.append(f"      - id: {yaml_escape(cid)}")
            lines.append(f"        title: {yaml_escape(title)}")
        lines.append("    # NOTE: Using hardcoded fallback — upstream fetch failed")

    lines.append("")
    lines.append("  mitre_atlas:")
    lines.append(f'    version: {yaml_escape(str(atlas_info.get("version", "unknown")))}')
    lines.append(f'    technique_count: {atlas_info.get("technique_count", 0)}')
    lines.append('    source: "https://github.com/mitre-atlas/atlas-navigator-data"')
    lines.append('    format: "STIX 2.1"')

    lines.append("")
    lines.append("  nist_ssdf:")
    lines.append('    version: "NIST SP 800-218A"')
    lines.append('    source: "https://csrc.nist.gov/pubs/sp/800/218/a/final"')
    lines.append('    note: "No machine-readable API; reference only"')
    lines.append("")

    # ── Secret Detection Patterns (from gitleaks) ──
    lines.append("# -- Secret Detection Patterns (from gitleaks upstream) --")
    lines.append(f"# Source: {SOURCES['gitleaks_toml']}")
    lines.append(f"# Pattern count: {len(gitleaks_patterns)}")
    lines.append("secret_patterns:")

    # Map gitleaks severity: generic-api-key → medium, most others → high
    for p in gitleaks_patterns:
        rule_id = p.get("id", "unknown")
        regex = p.get("regex", "")
        desc = p.get("description", rule_id)
        severity = "medium" if "generic" in rule_id.lower() else "high"
        confidence = "high" if "generic" not in rule_id.lower() else "medium"

        lines.append(f"  - rule_id: {yaml_escape('SEC-' + rule_id.upper())}")
        lines.append(f"    regex: {yaml_escape(regex)}")
        lines.append(f"    severity: {yaml_escape(severity)}")
        lines.append(f"    confidence: {yaml_escape(confidence)}")
        lines.append(f"    description: {yaml_escape(desc)}")
        lines.append(f'    owasp: "A04:2025 (Cryptographic Failures) / A07:2025 (Authentication Failures)"')
    lines.append("")

    # ── AI Node Type Prefixes ──
    lines.append("# -- AI / LangChain Node Types (from n8n GitHub) --")
    lines.append(f"# Source: {SOURCES['n8n_langchain_pkg']}")
    lines.append("ai_node_prefixes:")
    lines.append('  - "@n8n/n8n-nodes-langchain"')
    for cat in n8n_ai_categories:
        lines.append(f"  # Sub-category: {cat}")
    lines.append("")

    # ── Risky Node Patterns ──
    lines.append("# -- Risky Node Patterns (need error handling) --")
    lines.append("risky_node_patterns:")
    risky_configs = {
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
    for node_kw in n8n_risky_nodes:
        rec = risky_configs.get(node_kw, "Enable Retry on Fail and add an Error Workflow.")
        lines.append(f"  - pattern: {yaml_escape(node_kw)}")
        lines.append(f"    recommendation: {yaml_escape(rec)}")
    lines.append("")

    # ── Verdict Thresholds ──
    lines.append("# -- Verdict Thresholds --")
    lines.append("verdict:")
    lines.append("  max_medium_before_fail: 5")
    lines.append("  fail_on_any_high: true")
    lines.append("  fail_on_no_error_workflow: true")
    lines.append("  fail_on_open_webhook: true")
    lines.append("  fail_on_prompt_injection_path: true")
    lines.append("  fail_on_hardcoded_secret: true")
    lines.append("  fail_on_pindata_shipped: true")
    lines.append("")

    # ── Guardrail Keywords ──
    lines.append("# -- Guardrail Keywords (for AI prompt checks) --")
    lines.append("guardrail_keywords:")
    for kw in ["do not", "never", "refuse", "safe", "guardrail", "policy",
                "filter", "reject", "deny", "block", "restrict",
                "prohibited", "forbidden", "must not", "not allowed"]:
        lines.append(f"  - {yaml_escape(kw)}")
    lines.append("")

    return "\n".join(lines) + "\n"


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    print("=" * 60)
    print("n8n Audit Rules Updater")
    print("=" * 60)
    print()

    # 1. Fetch gitleaks patterns
    print("[1/5] Fetching gitleaks secret patterns...")
    raw = fetch_url(SOURCES["gitleaks_toml"])
    gitleaks_patterns = parse_gitleaks_toml(raw) if raw else []
    print(f"      → {len(gitleaks_patterns)} patterns extracted")

    # 2. Fetch OWASP Top 10 categories
    print("[2/5] Fetching OWASP Top 10:2025 categories...")
    raw = fetch_url(SOURCES["owasp_top10_index"])
    owasp_web = parse_owasp_top10_categories(raw) if raw else []
    print(f"      → {len(owasp_web)} categories extracted (fallback if 0)")

    # 3. Fetch OWASP LLM Top 10
    print("[3/5] Fetching OWASP LLM Top 10:2025 categories...")
    raw = fetch_url(SOURCES["owasp_llm_top10"])
    owasp_llm = parse_owasp_llm_categories(raw) if raw else []
    print(f"      → {len(owasp_llm)} categories extracted (fallback if 0)")

    # 4. Fetch MITRE ATLAS
    print("[4/5] Fetching MITRE ATLAS STIX data...")
    raw = fetch_url(SOURCES["atlas_stix"], timeout=60)
    atlas_info = parse_atlas_stix(raw) if raw else {"version": "unknown", "technique_count": 0}
    print(f"      → version={atlas_info['version']}, techniques={atlas_info['technique_count']}")

    # 5. Fetch n8n node types
    print("[5/5] Fetching n8n node type definitions...")
    raw_langchain = fetch_url(SOURCES["n8n_langchain_pkg"])
    raw_base = fetch_url(SOURCES["n8n_nodes_base_pkg"])
    n8n_ai_categories = parse_n8n_ai_node_types(raw_langchain) if raw_langchain else []
    n8n_risky_nodes = parse_n8n_risky_node_types(raw_base) if raw_base else []
    print(f"      → {len(n8n_ai_categories)} AI categories, {len(n8n_risky_nodes)} risky node types")

    # Generate YAML
    print()
    print("Generating audit_rules.yaml...")
    yaml_content = generate_yaml(
        gitleaks_patterns=gitleaks_patterns,
        owasp_web=owasp_web,
        owasp_llm=owasp_llm,
        atlas_info=atlas_info,
        n8n_ai_categories=n8n_ai_categories,
        n8n_risky_nodes=n8n_risky_nodes,
    )

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(yaml_content)

    print(f"  → Written to: {OUTPUT_PATH}")
    print(f"  → Size: {len(yaml_content)} bytes")
    print()
    print("Done. audit_rules.yaml is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
