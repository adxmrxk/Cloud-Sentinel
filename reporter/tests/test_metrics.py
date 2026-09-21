import app as reporter_app
import telemetry
from tests.helpers import AUDITOR_PAYLOAD, post


def _metrics(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    return response.get_data(as_text=True)


def _sample(text, name, **labels):
    for line in text.splitlines():
        if line.startswith(name + "{"):
            label_part = line[len(name) + 1 : line.index("}")]
            if all(f'{k}="{v}"' in label_part for k, v in labels.items()):
                return float(line.rsplit(" ", 1)[1])
    return None


def test_readme_metric_names_are_exported(client):
    post(client, AUDITOR_PAYLOAD)
    text = _metrics(client)
    for name in (
        "cloudsentinel_audits_total",
        "cloudsentinel_findings_by_severity",
        "cloudsentinel_scan_duration_seconds",
        "cloudsentinel_api_requests_total",
    ):
        assert name in text, name


def test_ingest_updates_business_metrics(client):
    labels = {"provider": "aws", "result": "vulnerable"}
    before = _sample(_metrics(client), "cloudsentinel_audits_total", **labels) or 0

    post(client, AUDITOR_PAYLOAD)
    after = _metrics(client)

    assert _sample(after, "cloudsentinel_audits_total", **labels) == before + 1
    by_severity = "cloudsentinel_findings_by_severity"
    assert _sample(after, by_severity, provider="aws", severity="CRITICAL") == 1
    assert _sample(after, by_severity, provider="aws", severity="MEDIUM") == 1
    assert _sample(after, by_severity, provider="aws", severity="HIGH") == 0


def test_request_metrics_use_route_templates(client):
    client.get("/health")
    client.get("/does-not-exist")
    text = _metrics(client)
    requests = "cloudsentinel_api_requests_total"
    assert _sample(text, requests, endpoint="/health", status="200") >= 1
    assert _sample(text, requests, endpoint="unmatched", status="404") >= 1


def test_posture_gauge_survives_a_restart(client, monkeypatch):
    post(client, AUDITOR_PAYLOAD)
    # Simulate a fresh process: in-memory gauge gone, restore not yet done.
    telemetry.FINDINGS_BY_SEVERITY.clear()
    monkeypatch.setattr(reporter_app, "_posture_restored", False)

    text = _metrics(client)
    by_severity = "cloudsentinel_findings_by_severity"
    assert _sample(text, by_severity, provider="aws", severity="CRITICAL") == 1
    assert _sample(text, by_severity, provider="aws", severity="MEDIUM") == 1
    assert reporter_app._posture_restored is True


def test_aws_clients_fail_fast():
    config = reporter_app.AWS_CLIENT_CONFIG
    assert config.connect_timeout <= 5
    assert config.read_timeout <= 15
