"""Slack delivery runs off the request path and retries failures."""

import threading
import time

import boto3

import app as reporter_app
import notifier
from tests.helpers import README_PAYLOAD, post


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _slack(monkeypatch, outcomes, delay=0.0):
    """Fake webhook answering with `outcomes` in turn; the last one repeats."""
    calls = []
    lock = threading.Lock()

    def fake_urlopen(req, timeout):
        with lock:
            calls.append(req.full_url)
            outcome = outcomes[min(len(calls), len(outcomes)) - 1]
        time.sleep(delay)
        return FakeResponse(*outcome)

    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setattr(reporter_app.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(notifier, "BASE_DELAY_SECONDS", 0)
    return calls


def _stored_flag():
    table = boto3.resource("dynamodb", region_name="us-east-1").Table("SecurityAudits")
    items = [i for i in table.scan()["Items"] if i.get("recordType") == "AUDIT"]
    return items[0]["slackNotified"]


def test_slow_webhook_does_not_delay_ingest(client, monkeypatch):
    monkeypatch.setenv("SLACK_DELIVERY", "async")
    _slack(monkeypatch, [(200, b"ok")], delay=1.5)

    started = time.perf_counter()
    response = post(client, README_PAYLOAD)
    elapsed = time.perf_counter() - started

    assert response.status_code == 201
    assert response.get_json()["slackNotification"] == "queued"
    assert elapsed < 1.0, f"ingest waited for Slack ({elapsed:.2f}s)"

    assert notifier.drain(timeout=10)
    assert _stored_flag() is True


def test_failed_deliveries_are_retried(client, monkeypatch):
    monkeypatch.setenv("SLACK_DELIVERY", "async")
    calls = _slack(monkeypatch, [(503, b"busy"), (500, b"err"), (200, b"ok")])

    post(client, README_PAYLOAD)
    assert notifier.drain(timeout=10)

    assert len(calls) == 3
    assert _stored_flag() is True


def test_gives_up_after_max_attempts(client, monkeypatch):
    monkeypatch.setenv("SLACK_DELIVERY", "async")
    calls = _slack(monkeypatch, [(503, b"busy")])

    post(client, README_PAYLOAD)
    assert notifier.drain(timeout=10)

    assert len(calls) == notifier.MAX_ATTEMPTS
    assert _stored_flag() is False


def test_sync_mode_retries_inline(client, monkeypatch):
    calls = _slack(monkeypatch, [(503, b"busy"), (200, b"ok")])
    response = post(client, README_PAYLOAD)
    assert response.get_json()["slackNotification"] == "sent"
    assert len(calls) == 2


def test_lambda_defaults_to_synchronous_delivery(monkeypatch):
    monkeypatch.delenv("SLACK_DELIVERY", raising=False)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "reporter")
    assert notifier.is_async() is False
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME")
    assert notifier.is_async() is True


def test_clean_audit_sends_nothing(client, monkeypatch):
    calls = _slack(monkeypatch, [(200, b"ok")])
    response = post(client, {"atRiskBuckets": [], "totalBucketsScanned": 2})
    assert response.get_json()["slackNotification"] == "not_needed"
    assert calls == []
