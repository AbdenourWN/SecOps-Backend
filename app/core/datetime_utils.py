"""
Centralised UTC datetime helpers. Always import from here — never define
utc_now() or to_utc() locally in individual modules.

Forbidden patterns caught by tests/test_utc_compliance.py:
  - datetime.utcnow()           — deprecated in Python 3.12, always naive
  - datetime.now()              — returns local time
  - datetime.fromtimestamp(x)   — returns local time unless tz= is passed
"""
from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    """Current UTC time, always tz-aware."""
    return datetime.now(timezone.utc)


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Attach UTC tzinfo to a naive datetime (e.g. from PyMongo, which strips
    tzinfo on roundtrip). Returns None if input is None.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
