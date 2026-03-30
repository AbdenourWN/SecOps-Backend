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

from elasticsearch import AsyncElasticsearch
from app.core.config import settings


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


async def connect_to_elasticsearch():
    """
    Connects to Elasticsearch when the API starts.
    Also creates the index templates.
    """
    try:
        es.client = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_URL],
            # No auth needed — we disabled xpack.security in Docker
        )

        # Verify connection (like MongoDB's ping)
        info = await es.client.info()
        print(f"✅ Connected to Elasticsearch: {info['version']['number']}")

        # Create/update the log index template
        await es.client.indices.put_index_template(
            name="secops-logs-template",
            body=LOG_INDEX_TEMPLATE,
        )
        
        # Create/update the metric index template
        await es.client.indices.put_index_template(
            name="secops-metrics-template",
            body=METRIC_INDEX_TEMPLATE,
        )
        print("⚡ Elasticsearch Index Templates Created")

    except Exception as e:
        print(f"⚠️ Elasticsearch not available: {e}")
        print("   Logs and Metrics will not be stored in ES. Start ES with: docker-compose up -d")
        es.client = None


async def close_elasticsearch():
    """Closes the ES connection when the API stops."""
    if es.client:
        await es.client.close()
        print("🛑 Elasticsearch connection closed.")


def get_elasticsearch():
    """
    Returns the ES client instance.
    Returns None if ES is not connected (app still works, just no log search).
    """
    return es.client
