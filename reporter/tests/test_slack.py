import io
import urllib.error

import app as reporter_app
from tests.helpers import README_PAYLOAD, post

BUCKETS = [{"BucketName": "b", "Severity": "CRITICAL", "RiskFactors": []}]


class FakeResponse(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _webhook(monkeypatch, status=200, body=b"ok", error=None):
    sent = {}

    def fake_urlopen(req, timeout):
        sent["url"] = req.full_url
        sent["data"] = req.data
        if error:
            raise error
        return FakeResponse(status, body)

    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setattr(reporter_app.urllib.request, "urlopen", fake_urlopen)
    return sent


def test_delivered_when_slack_answers_ok(aws, monkeypatch):
    sent = _webhook(monkeypatch)
    assert reporter_app.send_slack_alert("abcdef123", BUCKETS, 3) is True
    assert b"CloudSentinel Security Alert" in sent["data"]


def test_2xx_without_ok_body_is_not_delivery(aws, monkeypatch):
    # e.g. a proxy answering 200 for a webhook that never reached Slack
    _webhook(monkeypatch, status=200, body=b"<html>captive portal</html>")
    assert reporter_app.send_slack_alert("abcdef123", BUCKETS, 3) is False


def test_http_error_is_swallowed(aws, monkeypatch):
    _webhook(
        monkeypatch,
        error=urllib.error.HTTPError("u", 404, "no_service", {}, None),
    )
    assert reporter_app.send_slack_alert("abcdef123", BUCKETS, 3) is False


def test_placeholder_webhook_is_skipped(aws, monkeypatch):
    # Both the env var and the Secrets Manager fixture hold PLACEHOLDER URLs
    monkeypatch.setenv(
        "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/PLACEHOLDER"
    )
    assert reporter_app.send_slack_alert("abcdef123", BUCKETS, 3) is False


def test_ingest_reports_slack_outcome(client, monkeypatch):
    _webhook(monkeypatch)
    assert post(client, README_PAYLOAD).get_json()["slackNotified"] is True
