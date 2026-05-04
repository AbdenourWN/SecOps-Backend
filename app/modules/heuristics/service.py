"""
Tier 2 heuristic filter: cheap signals that flag rule-unmatched logs as
"interesting" without invoking AI.

Four heuristics:
  1. keyword filter           — matches a curated suspicious-token regex
  2. novel-pattern detection  — first time we see this log "shape" on this server
  3. time-of-day              — sensitive events outside business hours
  4. volume spike             — server log rate 10x its rolling EMA baseline
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, time as dtime, timezone
from typing import List, Optional, Tuple

from bson import ObjectId

from app.core.database import get_database
from app.modules.heuristics.keywords import DEFAULT_KEYWORDS, SENSITIVE_KEYWORDS


def _to_utc(dt: "datetime | None") -> "datetime | None":
    """Attach UTC tzinfo to a naive datetime returned by MongoDB."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ────────────────────────────────────────────────────────────────────────
# Keyword regex (compiled once at import)
# ────────────────────────────────────────────────────────────────────────

_env_kw = os.getenv("HEURISTIC_KEYWORDS", "").strip()
_keywords = (
    [w.strip().lower() for w in _env_kw.split(",") if w.strip()]
    if _env_kw
    else DEFAULT_KEYWORDS
)
_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in _keywords) + r")\b",
    re.IGNORECASE,
)
_SENSITIVE_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in SENSITIVE_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


# ────────────────────────────────────────────────────────────────────────
# Pattern normalization (novel-pattern detection)
# ────────────────────────────────────────────────────────────────────────

# Order matters: longest/most-specific patterns first.
_NORMALIZE_RULES: List[Tuple[re.Pattern, str]] = [
    # ISO 8601 timestamps
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TIME>"),
    # Syslog timestamps (Jan 24 10:30:15)
    (re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"), "<TIME>"),
    # IPv4
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<IP>"),
    # IPv6 (simple — covers the common cases)
    (re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE), "<IP>"),
    # UUIDs
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE), "<UUID>"),
    # PIDs in brackets (sshd[1234])
    (re.compile(r"\[\d+\]"), "[<PID>]"),
    # "port 51234" or "port: 22"
    (re.compile(r"\bport[:\s]+\d+\b", re.IGNORECASE), "port <PORT>"),
    # ":51234" right after an IP placeholder we just inserted
    (re.compile(r"<IP>:\d+\b"), "<IP>:<PORT>"),
    # Long hex strings (memory addresses, hashes) — 16+ hex chars
    (re.compile(r"\b(?:0x)?[0-9a-f]{16,}\b", re.IGNORECASE), "<HEX>"),
    # Large numbers (4+ digits) — sizes, byte counts, large IDs
    (re.compile(r"\b\d{4,}\b"), "<NUM>"),
]


def normalize_log_message(msg: str) -> str:
    """
    Strip noise (IPs, timestamps, PIDs, ports, UUIDs, large numbers) so that
    log lines with the same structure but different values produce the same hash.

    Keeps signal: usernames, file paths, command args, error class names,
    small numbers (exit codes).
    """
    out = msg
    for pat, repl in _NORMALIZE_RULES:
        out = pat.sub(repl, out)
    # Collapse runs of whitespace introduced by substitutions
    return re.sub(r"\s+", " ", out).strip()


def hash_pattern(normalized: str) -> str:
    """First 16 hex chars of SHA-256 of the normalized message (64 bits)."""
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


# ────────────────────────────────────────────────────────────────────────
# Time-of-day evaluation
# ────────────────────────────────────────────────────────────────────────

DEFAULT_BUSINESS_HOURS = {
    "start": "09:00",
    "end": "18:00",
    "days": [1, 2, 3, 4, 5],   # ISO weekday: Mon=1 .. Sun=7
    "tz": "UTC",
}


def _within_business_hours(ts: datetime, hours: dict) -> Tuple[bool, str]:
    """
    Returns (is_within, reason_if_outside). Reason is "" if within.
    Hours are interpreted in UTC for v1 (no per-server tz parsing yet).
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    iso_weekday = ts.isoweekday()
    if iso_weekday not in hours.get("days", DEFAULT_BUSINESS_HOURS["days"]):
        return False, "weekend" if iso_weekday in (6, 7) else "off_day"

    start_str = hours.get("start", "09:00")
    end_str = hours.get("end", "18:00")
    try:
        sh, sm = (int(x) for x in start_str.split(":"))
        eh, em = (int(x) for x in end_str.split(":"))
    except (ValueError, AttributeError):
        sh, sm, eh, em = 9, 0, 18, 0

    start = dtime(sh, sm)
    end = dtime(eh, em)
    cur = ts.time()
    if start <= cur < end:
        return True, ""
    return False, "after_hours" if cur >= end else "before_hours"


# ────────────────────────────────────────────────────────────────────────
# HeuristicService
# ────────────────────────────────────────────────────────────────────────

class HeuristicService:
    """Stateless evaluator. All persistent state lives in MongoDB."""

    async def evaluate(self, log: dict, server: dict) -> List[Tuple[str, int]]:
        """
        Run per-log heuristics on a rule-unmatched log.

        Returns list of (reason, score_delta) tuples. Empty list = no flag.
        Caller is responsible for inserting an observation if non-empty.

        Heuristic 1 (keyword) and 3 (time-of-day) run on every log.
        Heuristic 2 (novel pattern) consults `server_log_patterns` and is
        warm-up-aware.
        """
        flags: List[Tuple[str, int]] = []
        msg = log.get("message") or ""

        # 1. Keyword filter (cap at 5 keyword hits per log)
        kw_matches = _KEYWORD_RE.findall(msg)
        if kw_matches:
            unique = list(dict.fromkeys(m.lower() for m in kw_matches))[:5]
            for kw in unique:
                flags.append((f"keyword:{kw}", 1))

        # 3. Time-of-day on sensitive events
        if _SENSITIVE_RE.search(msg):
            ts = log.get("timestamp")
            if isinstance(ts, datetime):
                hours = server.get("business_hours") or DEFAULT_BUSINESS_HOURS
                inside, reason = _within_business_hours(ts, hours)
                if not inside:
                    flags.append((f"off_hours:{reason}", 2))

        # 2. Novel pattern (consult DB only if past warm-up)
        warmup_until = server.get("pattern_warmup_until")
        is_novel = await self._check_and_record_pattern(
            server_id=str(server["_id"]),
            msg=msg,
            in_warmup=bool(warmup_until and _to_utc(warmup_until) > datetime.now(timezone.utc)),
        )
        if is_novel:
            flags.append(("novel_pattern", 2))

        return flags

    async def _check_and_record_pattern(
        self,
        server_id: str,
        msg: str,
        in_warmup: bool,
    ) -> bool:
        """
        Looks up the normalized-log hash for this server.
          - If not seen: insert it. Return True ONLY if past warm-up.
          - If seen: bump seen_count. Return False.
        """
        if not msg:
            return False

        db = get_database()
        normalized = normalize_log_message(msg)
        if not normalized:
            return False
        h = hash_pattern(normalized)

        # Atomic upsert. setOnInsert sets first_seen_at; $inc bumps the counter.
        # We need to know whether this was a brand-new doc → use the Mongo
        # "upserted" return value rather than a separate find first.
        result = await db["server_log_patterns"].update_one(
            {"server_id": server_id, "pattern_hash": h},
            {
                "$setOnInsert": {
                    "server_id": server_id,
                    "pattern_hash": h,
                    "first_seen_at": datetime.now(timezone.utc),
                },
                "$inc": {"seen_count": 1},
            },
            upsert=True,
        )

        was_novel = result.upserted_id is not None
        return was_novel and not in_warmup

    # ────────────────────────────────────────────────────────────────────
    # Volume spike — runs once per server per telemetry tick
    # ────────────────────────────────────────────────────────────────────

    SPIKE_MULTIPLIER = 10
    BASELINE_MIN = 5            # don't flag 0 → 1 noise
    EMA_ALPHA = 0.05            # how fast the baseline tracks reality
    BASELINE_RESET_AFTER_S = 30 * 60  # 30 min idle → reset

    async def check_volume_spike(self, server: dict) -> Optional[Tuple[int, float, str]]:
        """
        Compares the last-60-second log count for this server against the EMA
        baseline kept on the server doc, then updates the baseline.

        Returns (current, baseline, reason) tuple if a spike is detected,
        else None. Caller inserts the observation.
        """
        from app.core.elasticsearch import get_elasticsearch
        from app.modules.logs.service import _get_log_index_name

        server_id = str(server["_id"])
        db = get_database()
        es_client = get_elasticsearch()

        # 1. Count logs in the last 60s for this server
        current = 0
        try:
            if es_client is not None:
                resp = await es_client.count(
                    index=_get_log_index_name(),
                    query={
                        "bool": {
                            "filter": [
                                {"term": {"server_id": server_id}},
                                {"range": {"timestamp": {"gte": "now-60s"}}},
                            ]
                        }
                    },
                    ignore_unavailable=True,
                )
                current = int(resp.get("count", 0))
        except Exception:
            # ES failure → treat as zero (don't crash telemetry)
            current = 0

        # 2. Read existing baseline (and check for staleness)
        now = datetime.now(timezone.utc)
        baseline = float(server.get("log_rate_baseline") or 0.0)
        last_updated = _to_utc(server.get("log_rate_updated_at"))
        if last_updated and (now - last_updated).total_seconds() > self.BASELINE_RESET_AFTER_S:
            baseline = 0.0  # stale — start fresh

        # 3. Decide flag BEFORE updating baseline (so a single spike
        #    doesn't poison its own comparison)
        multiplier = (server.get("detection_config") or {}).get("volume_spike_multiplier") or self.SPIKE_MULTIPLIER
        spike: Optional[Tuple[int, float, str]] = None
        if (
            baseline >= self.BASELINE_MIN
            and current > multiplier * baseline
        ):
            spike = (
                current,
                baseline,
                f"volume_spike:{current}x{int(baseline)}",
            )

        # 4. Update EMA baseline. If a spike was detected, fold the spike in
        #    at a smaller weight so a single huge value doesn't whipsaw the
        #    baseline upward and mask future spikes.
        weight = self.EMA_ALPHA if spike is None else (self.EMA_ALPHA / 5)
        new_baseline = (1 - weight) * baseline + weight * current
        await db["servers"].update_one(
            {"_id": ObjectId(server_id)},
            {
                "$set": {
                    "log_rate_baseline": new_baseline,
                    "log_rate_updated_at": now,
                }
            },
        )

        return spike
