"""
Elasticsearch Connection Manager
=================================
This is the ES equivalent of database.py for MongoDB.

HOW ELASTICSEARCH WORKS (Quick Guide):
- ES stores data in "indices" (like MongoDB collections)
- Each index has a "mapping" (like a schema) that defines field types
- We use time-based indices: "secops-logs-2026.03" so old data can be 
  easily deleted by dropping old indices
- ES automatically breaks text into searchable tokens 
  (e.g., "Failed password for root" → ["failed", "password", "for", "root"])
- This is called "analysis" and it enables instant full-text search

FIELD TYPES TO KNOW:
- "text"    → Analyzed (searchable by words). Use for log messages.
- "keyword" → Exact match only (not analyzed). Use for server_id, level, etc.
- "date"    → Dates. ES can parse ISO format automatically.
"""

import asyncio
import logging

from elasticsearch import AsyncElasticsearch
from app.core.config import settings

logger = logging.getLogger(__name__)


class ElasticClient:
    """Holds the ES client instance — same pattern as the MongoDB Database class."""
    client: AsyncElasticsearch = None


es = ElasticClient()

# -- The index template defines how ALL secops-logs-* indices are structured --
# Think of this like a Pydantic model, but for Elasticsearch.
LOG_INDEX_TEMPLATE = {
    "index_patterns": ["secops-logs-*"],
    "template": {
        "settings": {
            # 1 shard is fine for single-node dev. In production you'd use more.
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                # -- When was this log generated? --
                "timestamp": {"type": "date"},
                # -- Who generated it? --
                "server_id": {"type": "keyword"},      # Exact match (filter by server)
                "hostname": {"type": "keyword"},         # For display
                "source": {"type": "keyword"},           # e.g., "journalctl", "file_watcher"
                # -- The log content --
                "message": {"type": "text"},             # <-- ANALYZED: full-text searchable!
                "level": {"type": "keyword"},            # INFO, WARNING, ERROR, etc.
                # -- Metadata --
                "os_type": {"type": "keyword"},          # linux / windows
                "log_source": {"type": "keyword"},       # file path or "system"
                "ingested_at": {"type": "date"},         # When we collected it
            }
        }
    }
}


# -- The index template for METRICS --
METRIC_INDEX_TEMPLATE = {
    "index_patterns": ["secops-metrics-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "server_id": {"type": "keyword"},
                "cpu_usage": {"type": "float"},
                "ram_usage": {"type": "float"},
                "disk_usage": {"type": "float"},
                "raw_data": {"type": "text"}
            }
        }
    }
}


async def _verify_and_setup() -> bool:
    """
    Ping ES and (re)apply the index templates. Returns True on success.

    Kept separate from connect_to_elasticsearch() so a background task can retry
    it after a startup race without reconstructing the client.
    """
    if es.client is None:
        return False
    try:
        info = await es.client.info()
        await es.client.indices.put_index_template(
            name="secops-logs-template",
            body=LOG_INDEX_TEMPLATE,
        )
        await es.client.indices.put_index_template(
            name="secops-metrics-template",
            body=METRIC_INDEX_TEMPLATE,
        )
        logger.info(
            "Connected to Elasticsearch %s — index templates applied",
            info["version"]["number"],
        )
        return True
    except Exception as e:
        logger.warning("Elasticsearch not ready yet (%s)", e)
        return False


async def _background_reconnect(max_attempts: int = 60, delay_s: float = 5.0) -> None:
    """
    Retry the ES health check + template setup in the background.

    WHY: AsyncElasticsearch connects lazily per-request, so the client object is
    always kept. But the eager startup ping fails if ES isn't ready yet — the
    common case when ES and the backend are restarted together (ES needs
    ~30-60s to accept connections). Rather than permanently disabling logs/
    metrics (the old behaviour, which set es.client = None), we retry here so the
    pipeline self-heals once ES is reachable — no backend restart required.
    """
    for _ in range(max_attempts):
        await asyncio.sleep(delay_s)
        if await _verify_and_setup():
            return
    logger.warning(
        "Elasticsearch still unverified after %d attempts (~%.0fs) — client kept; "
        "reads/writes will keep retrying lazily on each request.",
        max_attempts, max_attempts * delay_s,
    )


async def connect_to_elasticsearch():
    """
    Initialise the Elasticsearch client when the API starts and apply the index
    templates.

    IMPORTANT: the client is created and KEPT even if the startup health check
    fails. AsyncElasticsearch dials lazily on the first request and manages its
    own reconnection, so keeping it lets logs/metrics recover automatically once
    ES becomes reachable. If the initial verification fails we kick off a
    background retry (templates + ping) instead of nulling the client — this is
    what makes the pipeline resilient to an ES/backend co-restart race.
    """
    try:
        es.client = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_URL],
            # No auth needed — we disabled xpack.security in Docker
        )
    except Exception as e:
        # Only a malformed URL / config error reaches here (construction is
        # otherwise lazy). Nothing to keep in that case.
        logger.warning("Could not construct Elasticsearch client (%s) — logs/metrics disabled.", e)
        es.client = None
        return

    if not await _verify_and_setup():
        logger.warning(
            "Elasticsearch not verified at startup — client kept; retrying in the "
            "background so logs/metrics self-heal once ES is reachable.",
        )
        asyncio.create_task(_background_reconnect())


async def close_elasticsearch():
    """Closes the ES connection when the API stops."""
    if es.client:
        await es.client.close()
        logger.info("Elasticsearch connection closed")


def get_elasticsearch():
    """
    Returns the ES client instance.
    Returns None if ES is not connected (app still works, just no log search).
    """
    return es.client
