"""Structured logging configuration (Phase 20.4).

Single entry point `configure_logging()` installs a JSON (or plain-text) formatter
on the root logger so every `logging.getLogger(__name__)` call across the backend
emits consistent, parseable records on stdout. Idempotent — safe to call more than
once. Honors `LOG_LEVEL` / `LOG_JSON` from settings.

Usage (one line, at startup in `main.py`):

    from app.core.logging_config import configure_logging
    configure_logging()

Modules log via the stdlib:

    import logging
    logger = logging.getLogger(__name__)
    logger.info("server %s came online", hostname)        # lazy %-args
    logger.warning("skipping collection — server offline")
    logger.exception("remediation failed")                # inside an except block
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from app.core.config import settings

_CONFIGURED = False

# Standard LogRecord attributes. Anything NOT in here that lands on a record is
# treated as a structured "extra" (passed via logger.x(..., extra={...})) and
# merged into the JSON output.
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}

# Third-party loggers that are chatty at INFO; pin to WARNING so our own INFO
# records stay readable.
_NOISY = ("pymongo", "elastic_transport", "elasticsearch", "httpx", "httpcore", "asyncio")


class JsonFormatter(logging.Formatter):
    """Compact one-line JSON per record: ts / level / logger / msg (+ exc, + extras)."""

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            out["stack"] = self.formatStack(record.stack_info)
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                out[key] = value
        return json.dumps(out, default=str, ensure_ascii=False)


def configure_logging() -> None:
    """Install the root stdout handler + formatter. Safe to call repeatedly."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = getattr(logging, str(settings.LOG_LEVEL).upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    if settings.LOG_JSON:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Route uvicorn's loggers through our handler instead of its own (no dupes).
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True

    # Quiet noisy third-party INFO chatter.
    for name in _NOISY:
        logging.getLogger(name).setLevel(logging.WARNING)

    _CONFIGURED = True
