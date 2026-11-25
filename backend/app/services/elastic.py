import logging
import time
import urllib.request
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from app.config import ELASTICSEARCH_HOSTS, ELASTICSEARCH_INDEX, AGENT_LOGS_ES_INDEX, ES_USERNAME, ES_PASSWORD

logger = logging.getLogger(__name__)

# Short timeouts + no retries: when the cluster is down we want fast failure,
# not transport-level backoff that can block a worker thread for 15-30s.
es_kwargs = {"request_timeout": 2, "retry_on_timeout": False, "max_retries": 0}
if ES_USERNAME and ES_PASSWORD:
    es_kwargs["basic_auth"] = (ES_USERNAME, ES_PASSWORD)

es = Elasticsearch(ELASTICSEARCH_HOSTS, **es_kwargs)

_UP_CHECK_INTERVAL = 2.0
_last_check = 0.0
_es_up_cached = True


def _es_up() -> bool:
    """Fast liveness probe with negative caching.

    Uses a fresh urllib connection (timeout=1s) instead of the ES client, so a
    down cluster is detected in milliseconds — the client's node pool would
    otherwise block every call for up to ~30s once it has seen 50 failures.
    """
    global _last_check, _es_up_cached
    now = time.monotonic()
    if now - _last_check < _UP_CHECK_INTERVAL:
        return _es_up_cached
    _last_check = now
    try:
        host = ELASTICSEARCH_HOSTS.split(",")[0].strip().rstrip("/")
        # Prefer real cluster health (catches red clusters a root ping
        # misses); fall back to the root probe for locked-down endpoints.
        probed = False
        for path in ("/_cluster/health?timeout=500ms", "/"):
            try:
                with urllib.request.urlopen(f"{host}{path}", timeout=0.5):  # noqa: S310 - local health probe
                    probed = True
                    break
            except Exception:
                continue
        _es_up_cached = probed
    except Exception:
        _es_up_cached = False
    return _es_up_cached


def es_healthy() -> bool:
    return _es_up()


def ensure_index():
    if not _es_up():
        logger.warning("Elasticsearch not available, skipping index creation")
        return
    try:
        if not es.indices.exists(index=ELASTICSEARCH_INDEX):
            es.indices.create(index=ELASTICSEARCH_INDEX, body={
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "project_id": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "hostname": {"type": "keyword"},
                        "raw": {"type": "object"},
                        "enriched": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "geo": {"type": "object"},
                                "user_agent_parsed": {"type": "text"},
                                "risk_score": {"type": "float"},
                                "severity": {"type": "keyword"},
                            }
                        },
                        "tags": {"type": "keyword"},
                    }
                }
            })
        if not es.indices.exists(index=AGENT_LOGS_ES_INDEX):
            es.indices.create(index=AGENT_LOGS_ES_INDEX, body={
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "agent_id": {"type": "keyword"},
                        "level": {"type": "keyword"},
                        "stage": {"type": "keyword"},
                        "message": {"type": "text"},
                        "hostname": {"type": "keyword"},
                        "meta": {"type": "object"},
                    }
                }
            })
    except Exception:
        logger.warning("Elasticsearch not available, skipping index creation")


def index_event(event: dict) -> str | None:
    if not _es_up():
        return None
    try:
        doc_id = event.get("id")
        kwargs = {"index": ELASTICSEARCH_INDEX, "body": event, "refresh": "wait_for"}
        if doc_id:
            kwargs["id"] = doc_id
        resp = es.index(**kwargs)
        return resp["_id"]
    except Exception:
        logger.warning("Failed to index event in ES (ES may be down)")
        return None


def index_agent_log(doc: dict) -> str | None:
    if not _es_up():
        return None
    try:
        resp = es.index(index=AGENT_LOGS_ES_INDEX, body=doc)
        return resp["_id"]
    except Exception:
        logger.warning("Failed to index agent log in ES")
        return None


def search_events(
    project_id: int,
    query: str = None,
    severity: str = None,
    source: str = None,
    event_type: str = None,
    time_from: str = None,
    time_to: str = None,
    size: int = 50,
    offset: int = 0,
    host: str = None,
):
    if not _es_up():
        return [], 0
    try:
        must = [{"term": {"project_id": str(project_id)}}]
        if query:
            must.append({"simple_query_string": {"query": query}})
        if severity:
            must.append({
                "bool": {
                    "should": [
                        {"term": {"event_type": severity}},
                        {"term": {"enriched.severity": severity}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if source:
            must.append({"term": {"source": source}})
        if event_type:
            must.append({
                "bool": {
                    "should": [
                        {"term": {"event_type": event_type}},
                        {"term": {"enriched.severity": event_type}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if host:
            must.append({
                "bool": {
                    "should": [
                        {"wildcard": {"hostname.keyword": f"*{host}*"}},
                        {"wildcard": {"raw.hostname.keyword": f"*{host}*"}},
                        {"match_phrase": {"hostname": host}},
                        {"match_phrase": {"raw.hostname": host}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if time_from or time_to:
            range_filter = {}
            if time_from:
                range_filter["gte"] = time_from
            if time_to:
                range_filter["lte"] = time_to
            must.append({"range": {"timestamp": range_filter}})

        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
            "from": offset,
        }
        resp = es.search(index=ELASTICSEARCH_INDEX, body=body)
        hits = resp["hits"]["hits"]
        return [
            {"id": h["_source"].get("id") or h["_id"], **h["_source"]}
            for h in hits
        ], resp["hits"]["total"]["value"]
    except Exception:
        logger.warning("search_events failed (ES may be down)")
        return [], 0


def get_aggregations(project_id: int, field: str, size: int = 10):
    if not _es_up():
        return []
    try:
        body = {
            "query": {"term": {"project_id": str(project_id)}},
            "size": 0,
            "aggs": {
                "group_by": {
                    "terms": {"field": field, "size": size}
                }
            }
        }
        resp = es.search(index=ELASTICSEARCH_INDEX, body=body)
        buckets = resp["aggregations"]["group_by"]["buckets"]
        return [{"key": b["key"], "count": b["doc_count"]} for b in buckets]
    except Exception:
        logger.warning("get_aggregations failed (ES may be down)")
        return []


def get_event_by_id(event_id: str):
    if not _es_up():
        return None
    try:
        resp = es.get(index=ELASTICSEARCH_INDEX, id=event_id)
        if not resp.get("found"):
            return None
        return {"id": resp["_id"], **resp["_source"]}
    except Exception as exc:
        if getattr(exc, "status_code", None) == 404 or "NotFoundError" in type(exc).__name__:
            return None
        logger.warning("get_event_by_id failed (ES may be down)")
        return None


def _bulk_index(index: str, docs: list[dict]):
    if not docs:
        return
    if not _es_up():
        return 0
    actions = []
    for doc in docs:
        action = {"_index": index, "_source": doc}
        if doc.get("id"):
            action["_id"] = doc["id"]
        actions.append(action)
    try:
        success, errors = bulk(es, actions, raise_on_error=False, refresh=False)
        if errors:
            logger.warning("Bulk ES indexing finished with %d errors out of %d docs", len(errors), len(docs))
        return success
    except Exception:
        logger.warning("Bulk ES indexing failed (ES may be down)")
        return 0


def index_events_bulk(events: list[dict]):
    return _bulk_index(ELASTICSEARCH_INDEX, events)


def index_agent_logs_bulk(logs: list[dict]):
    return _bulk_index(AGENT_LOGS_ES_INDEX, logs)


def delete_events_by_query(project_id: int, source: str = None, before: str = None,
                           hostname: str = None) -> int:
    """Delete event docs from the ES events index matching project/source/before/hostname.

    Called by the log-cleanup flow so ES never resurrects deleted events in
    search. Returns the deleted count, or -1 when ES was unreachable (Mongo
    is the source of truth, so cleanup still works — the caller reports the
    pending sync instead of silently dropping it).
    """
    if not _es_up():
        return -1
    try:
        must = [{"term": {"project_id": str(project_id)}}]
        if source:
            must.append({"term": {"source": source}})
        if hostname:
            must.append({
                "bool": {
                    "should": [
                        {"term": {"hostname": hostname}},
                        {"term": {"hostname.keyword": hostname}},
                        {"term": {"raw.hostname.keyword": hostname}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if before:
            must.append({"range": {"timestamp": {"lt": before}}})
        resp = es.delete_by_query(
            index=ELASTICSEARCH_INDEX,
            body={"query": {"bool": {"must": must}}},
            conflicts="proceed",
            refresh=True,
            request_timeout=30,
        )
        return resp.get("deleted", 0)
    except Exception:
        logger.warning("delete_by_query failed (ES may be down)")
        return -1


def delete_agent_logs_by_query(project_id: int, before: str = None, hostname: str = None) -> int:
    """Delete raw agent-log docs from the ES agent-logs index (-1 if unreachable)."""
    if not _es_up():
        return -1
    try:
        must = [{"term": {"project_id": str(project_id)}}]
        if hostname:
            must.append({"term": {"hostname": hostname}})
        if before:
            must.append({"range": {"timestamp": {"lt": before}}})
        resp = es.delete_by_query(
            index=AGENT_LOGS_ES_INDEX,
            body={"query": {"bool": {"must": must}}},
            conflicts="proceed",
            refresh=True,
            request_timeout=30,
        )
        return resp.get("deleted", 0)
    except Exception:
        logger.warning("agent-log delete_by_query failed (ES may be down)")
        return -1
