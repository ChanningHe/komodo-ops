"""
Pre-commit secrets leak detection.

Reads unified diff from stdin, checks for:
  1. Known API key prefixes
  2. High-entropy strings
  3. Private patterns from external config
  4. Semantic secrets (secret-named keys with hardcoded values)

Exit 0 = clean, Exit 1 = issues found.
"""

import math

# import os
import re
import sys
from collections import Counter
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent
PATTERNS_FILE = HOOK_DIR / "secrets-patterns"

RED = "\033[0;31m"
CYAN = "\033[0;36m"
NC = "\033[0m"

# ── Module 1: Known secret prefixes ──────────────────────────

KNOWN_PREFIXES = [
    (re.compile(r"sk-proj-[a-zA-Z0-9]{20,}"), "OpenAI API Key"),
    (re.compile(r"sk-ant-[a-zA-Z0-9]{20,}"), "Anthropic API Key"),
    (re.compile(r"sk-[a-f0-9]{32,}"), "DeepSeek/Generic SK Key"),
    (re.compile(r"AIzaSy[a-zA-Z0-9_-]{33}"), "Google API Key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth Token"),
    (re.compile(r"ghs_[a-zA-Z0-9]{36}"), "GitHub App Token"),
    (re.compile(r"glpat-[a-zA-Z0-9_-]{20,}"), "GitLab Personal Access Token"),
    (re.compile(r"xox[baprs]-[a-zA-Z0-9-]{10,}"), "Slack Token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"whsec_[a-zA-Z0-9]{32,}"), "Stripe Webhook Secret"),
    (re.compile(r"sk_live_[a-zA-Z0-9]{24,}"), "Stripe Live Key"),
]

# ── Module 4: Semantic secret key names ──────────────────────

SECRET_KEY_RE = re.compile(
    r"[A-Z_]*("
    r"PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|"
    r"AUTH_KEY|ENCRYPTION_KEY|SIGNING_KEY|JWT_SECRET|DB_PASS|REDIS_PASS"
    r")[A-Z_]*",
)

# Variable reference patterns (safe to allow)
VAR_REF_RE = re.compile(r"^\$\{|^\$[A-Z_]|^\[\[")

# Value extractor: after = or : , optionally quoted
VALUE_AFTER_EQ = re.compile(r"""=\s*['"]?([^'"#\s].*?)['"]?\s*(?:#.*)?$""")
VALUE_AFTER_COLON = re.compile(r""":\s+['"]?([^'"#\s].*?)['"]?\s*(?:#.*)?$""")

# High-entropy value candidate: alphanumeric + base64 chars, ≥24 long
ENTROPY_CANDIDATE_RE = re.compile(r"""[=:]\s*['"]?([a-zA-Z0-9+/=_-]{24,})['"]?""")

# Config file extensions worth scanning for entropy / semantic checks
CONFIG_EXTS = {".yaml", ".yml", ".toml", ".env", ".conf"}


def shannon_entropy(s: str) -> float:
    if len(s) < 16:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_var_ref(val: str) -> bool:
    return bool(VAR_REF_RE.match(val))


def load_private_patterns() -> list[re.Pattern]:
    if not PATTERNS_FILE.is_file():
        return []
    patterns = []
    for line in PATTERNS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(re.compile(line))
        except re.error:
            pass
    return patterns


def report(module: str, filepath: str, detail: str) -> None:
    print(f"{RED}[BLOCKED]{NC} {CYAN}[{module}]{NC} {filepath}")
    print(f"  → {detail}")


def parse_diff(diff_text: str):
    """Yield (filepath, added_line_content) for each added line in the diff."""
    current_file = ""
    for line in diff_text.splitlines():
        m = re.match(r"^diff --git a/(.*?) b/", line)
        if m:
            current_file = m.group(1)
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        yield current_file, line[1:]


def ext_of(filepath: str) -> str:
    # Handle compound extensions like compose.env
    if filepath.endswith(".env"):
        return ".env"
    return Path(filepath).suffix


def main() -> int:
    diff_text = sys.stdin.read()
    if not diff_text.strip():
        print("No staged changes to check.")
        return 0

    private_patterns = load_private_patterns()
    issues = 0

    for filepath, content in parse_diff(diff_text):
        stripped = content.lstrip()

        # Skip comments
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        ext = ext_of(filepath)

        # ── Module 1: Known prefixes ──
        for pattern, desc in KNOWN_PREFIXES:
            if pattern.search(content):
                report("secret-prefix", filepath, f"Detected {desc} pattern")
                issues += 1

        # ── Module 3: Private patterns ──
        if not filepath.startswith(".githooks/"):
            for pat in private_patterns:
                if pat.search(content):
                    report(
                        "private-pattern",
                        filepath,
                        f"Matched private pattern: {pat.pattern}",
                    )
                    issues += 1
                    break

        # Only do config-aware checks on relevant file types
        if ext not in CONFIG_EXTS:
            continue

        # ── Module 2: High-entropy detection ──
        m = ENTROPY_CANDIDATE_RE.search(content)
        if m:
            val = m.group(1)
            if not is_var_ref(val) and "/" not in val:
                ent = shannon_entropy(val)
                if ent > 4.0:
                    report(
                        "high-entropy",
                        filepath,
                        f"High entropy value ({ent:.2f} bits): {val[:12]}...",
                    )
                    issues += 1

        # ── Module 4: Semantic secret detection ──
        if ext == ".env":
            # KEY=VALUE format
            eq_pos = content.find("=")
            if eq_pos > 0:
                key_part = (
                    content[:eq_pos].strip().split()[-1]
                    if content[:eq_pos].strip()
                    else ""
                )
                if SECRET_KEY_RE.search(key_part):
                    val = content[eq_pos + 1 :].strip().strip("'\"")
                    if val and not is_var_ref(val):
                        report(
                            "semantic-secret",
                            filepath,
                            f"Hardcoded secret: {key_part}=<redacted>",
                        )
                        issues += 1

        elif ext in (".yaml", ".yml"):
            if SECRET_KEY_RE.search(content):
                val = None
                m_eq = VALUE_AFTER_EQ.search(content)
                m_col = VALUE_AFTER_COLON.search(content)
                if m_eq:
                    val = m_eq.group(1).strip("'\"")
                elif m_col:
                    val = m_col.group(1).strip("'\"")
                if val and not is_var_ref(val):
                    # Extract key name for reporting
                    km = SECRET_KEY_RE.search(content)
                    key = km.group(0) if km else "<key>"
                    report(
                        "semantic-secret",
                        filepath,
                        f"Hardcoded secret in YAML: {key}=<redacted>",
                    )
                    issues += 1

        elif ext == ".toml":
            m_toml = re.match(r'^value\s*=\s*"(.+)"', stripped)
            if m_toml:
                val = m_toml.group(1)
                if not is_var_ref(val) and len(val) >= 20:
                    ent = shannon_entropy(val)
                    if ent > 3.5:
                        report(
                            "semantic-secret",
                            filepath,
                            f"Suspicious TOML value ({ent:.2f} bits entropy): {val[:8]}...",
                        )
                        issues += 1

    return issues


if __name__ == "__main__":
    print("=== Pre-commit: secrets leak detection ===")
    issues = main()
    print()
    if issues > 0:
        print(
            f"{RED}✗ Blocked: {issues} issue(s) found. Fix them or use --no-verify to bypass (not recommended).{NC}"
        )
        sys.exit(1)
    else:
        print("✓ No secrets detected. Commit allowed.")
        sys.exit(0)
