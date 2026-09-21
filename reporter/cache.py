"""
Redis read-through cache for the reporter.

The dashboard's first page (newest audits plus running totals) is cached
here and invalidated whenever a new audit is ingested or a Slack delivery
result is recorded.

Configured by REDIS_URL, or REDIS_HOST/REDIS_PORT (the Kubernetes manifests
use the latter). When neither is set - for example in Lambda - caching is
disabled and every call is a miss. Redis failures are logged and treated as
misses so the cache can never take the dashboard down.
"""

import json
import logging
import os
from decimal import Decimal

import redis

from telemetry import CACHE_OPERATIONS

log = logging.getLogger(__name__)

# First dashboard page plus running totals (v1 held every audit).
AUDITS_KEY = "cloudsentinel:dashboard:v2"

_client = None


def _redis_url():
    url = (os.environ.get("REDIS_URL") or "").strip()
    if url:
        return url
    host = (os.environ.get("REDIS_HOST") or "").strip()
    if host:
        port = os.environ.get("REDIS_PORT", "6379")
        return f"redis://{host}:{port}/0"
    return None


def ttl_seconds():
    return int(os.environ.get("CACHE_TTL_SECONDS", "60"))


def get_client():
    """Return a Redis client, or None when caching is not configured."""
    global _client
    if _client is None:
        url = _redis_url()
        if not url:
            return None
        _client = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
    return _client


def reset():
    """Forget the cached client (used by tests and after config changes)."""
    global _client
    _client = None


def _to_json(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def get_json(key):
    client = get_client()
    if client is None:
        return None
    try:
        raw = client.get(key)
    except redis.RedisError as e:
        CACHE_OPERATIONS.labels("get", "error").inc()
        log.warning("Redis get failed for %s: %s", key, e)
        return None
    if raw is None:
        CACHE_OPERATIONS.labels("get", "miss").inc()
        return None
    CACHE_OPERATIONS.labels("get", "hit").inc()
    return json.loads(raw)


def set_json(key, value, ttl=None):
    client = get_client()
    if client is None:
        return False
    try:
        client.set(key, json.dumps(value, default=_to_json), ex=ttl or ttl_seconds())
    except redis.RedisError as e:
        CACHE_OPERATIONS.labels("set", "error").inc()
        log.warning("Redis set failed for %s: %s", key, e)
        return False
    CACHE_OPERATIONS.labels("set", "ok").inc()
    return True


def delete(key):
    client = get_client()
    if client is None:
        return False
    try:
        client.delete(key)
    except redis.RedisError as e:
        CACHE_OPERATIONS.labels("delete", "error").inc()
        log.warning("Redis delete failed for %s: %s", key, e)
        return False
    CACHE_OPERATIONS.labels("delete", "ok").inc()
    return True
