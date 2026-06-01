"""
Helpers for returning clean, user-facing API errors.

`http_error()` builds an `HTTPException` whose `detail` is a short, plain-English
message safe to show the user — never a raw exception / stack trace. When an
underlying exception is supplied it is logged server-side with a short
correlation id (mirroring the global handler in `main.py`), and that id is
appended to the user message so a bug report can be traced back to the log line.

Use this at server-fault sites (500/503) where the previous code did
`detail=f"...: {exc}"`. Deliberate input-validation errors (400) that raise a
meaningful `ValueError` may keep passing `str(exc)` — that text is written for
the user, not a compiler dump.
"""
import logging
import uuid
from typing import Optional

from fastapi import HTTPException

_logger = logging.getLogger("secops.api")


def http_error(
    status_code: int,
    message: str,
    exc: Optional[BaseException] = None,
    context: str = "",
) -> HTTPException:
    """Return an HTTPException with a user-safe message; log the raw cause server-side."""
    if exc is not None:
        ref = str(uuid.uuid4())[:8]
        _logger.error(
            "API error [%s] %s — %s: %s",
            ref,
            context or "request",
            type(exc).__name__,
            exc,
        )
        message = f"{message} (ref: {ref})"
    return HTTPException(status_code=status_code, detail=message)
