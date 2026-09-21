import re

import redis

import app as reporter_app
import cache
from tests.helpers import README_PAYLOAD, post


def _total_audits(html):
    match = re.search(
        r'stat-value">\s*(\d+)\s*</div>\s*<div class="stat-label">Total Audits', html
    )
    return int(match.group(1))


def test_dashboard_is_served_from_redis_on_second_request(
    client, redis_cache, monkeypatch
):
    post(client, README_PAYLOAD)
    assert client.get("/").status_code == 200  # miss: scans DynamoDB, fills cache
    assert redis_cache.get(cache.AUDITS_KEY) is not None

    def fail(**_):
        raise AssertionError("DynamoDB was read despite a warm cache")

    for method in ("scan", "query", "get_item"):
        monkeypatch.setattr(reporter_app.get_table(), method, fail)
    response = client.get("/")
    assert response.status_code == 200
    assert "demo-bucket" in response.get_data(as_text=True)


def test_ingest_invalidates_cache(client, redis_cache):
    post(client, README_PAYLOAD)
    client.get("/")
    assert redis_cache.get(cache.AUDITS_KEY) is not None

    post(client, README_PAYLOAD)
    assert redis_cache.get(cache.AUDITS_KEY) is None
    assert _total_audits(client.get("/").get_data(as_text=True)) == 2


def test_redis_outage_falls_back_to_dynamodb(client, monkeypatch):
    class Down:
        def get(self, *_):
            raise redis.ConnectionError("down")

        def set(self, *_, **__):
            raise redis.ConnectionError("down")

        def delete(self, *_):
            raise redis.ConnectionError("down")

    monkeypatch.setattr(cache, "_client", Down())
    assert post(client, README_PAYLOAD).status_code == 201
    response = client.get("/")
    assert response.status_code == 200
    assert "demo-bucket" in response.get_data(as_text=True)


def test_cache_disabled_without_configuration(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)
    cache.reset()
    assert cache.get_client() is None
    assert cache.get_json("anything") is None


def test_redis_host_and_port_are_supported(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("REDIS_HOST", "redis-service")
    monkeypatch.setenv("REDIS_PORT", "6380")
    assert cache._redis_url() == "redis://redis-service:6380/0"
