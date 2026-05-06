"""
Anomaly observation fingerprinting.

A fingerprint collapses repeated occurrences of the same logical anomaly
(same server, same type, same normalized message shape, same reasons) into
a single 16-character hex key.  Used by the upsert-based aggregation in
service.py to prevent observation floods.
"""

import hashlib
from typing import List

from app.modules.heuristics.service import hash_pattern, normalize_log_message


def compute_fingerprint(
    server_id: str,
    type_: str,
    message: str,
    reasons: List[str],
) -> str:
    """
    Return a 16-hex-char fingerprint for an observation.

    For log observations the fingerprint encodes:
        server_id | type | normalized-message-hash | sorted-reasons

    For volume observations (empty message) it reduces to:
        server_id | "volume" | "" | sorted-reasons
    so all volume spikes on a server collapse to one active row.
    """
    if message:
        normalized = normalize_log_message(message)
        msg_hash = hash_pattern(normalized)
    else:
        msg_hash = ""

    reasons_part = ",".join(sorted(reasons))
    raw = f"{server_id}|{type_}|{msg_hash}|{reasons_part}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
