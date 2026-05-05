"""
Static compliance check: ensures no naive-datetime regressions slip into the codebase.

Forbidden patterns:
  - datetime.utcnow()                    — deprecated in Python 3.12, always naive
  - datetime.now()  (no argument)        — returns local time, not UTC
  - datetime.fromtimestamp(x) without tz= — returns local time

Run:
    pytest test_utc_compliance.py
"""
import re
from pathlib import Path

ROOT = Path(__file__).parent
APP_DIR = ROOT / "app"

FORBIDDEN = [
    (
        re.compile(r"\bdatetime\.utcnow\s*\("),
        "datetime.utcnow() is deprecated; use utc_now() from app.core.datetime_utils",
    ),
    (
        re.compile(r"\bdatetime\.now\s*\(\s*\)"),
        "datetime.now() returns local time; use utc_now() from app.core.datetime_utils",
    ),
    (
        re.compile(r"\bdatetime\.fromtimestamp\s*\([^)]*\)"),
        "datetime.fromtimestamp() requires tz=timezone.utc",
    ),
]

# The helper module itself defines the canonical pattern — exclude it from checks.
EXCLUDED = {
    "app/core/datetime_utils.py",
}


def test_no_naive_datetime_usage():
    violations = []
    for py_file in APP_DIR.rglob("*.py"):
        rel = py_file.relative_to(ROOT).as_posix()
        if rel in EXCLUDED:
            continue
        text = py_file.read_text(encoding="utf-8")
        for pattern, msg in FORBIDDEN:
            for match in pattern.finditer(text):
                # fromtimestamp with tz= kwarg is allowed
                if "fromtimestamp" in match.group() and "tz=" in match.group():
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                violations.append(f"{rel}:{line_no}  →  {msg}")

    assert not violations, (
        f"\n{len(violations)} naive-datetime violation(s) found:\n"
        + "\n".join(violations)
    )
