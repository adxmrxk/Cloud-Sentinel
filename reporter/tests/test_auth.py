"""/ingest must refuse writes from callers without the API key."""

import json

import pytest

from tests.helpers import AUDITOR_PAYLOAD, post

FORGED_CLEAN = {
    "vulnerabilitiesFound": False,
    "atRiskBuckets": [],
    "totalBucketsScanned": 3,
    "cloudProvider": "aws",
}


def _raw_post(client, headers):
    return client.post(
        "/ingest",
        data=json.dumps(FORGED_CLEAN),
        content_type="application/json",
        headers=headers,
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic dGVzdC1pbmdlc3Qta2V5"},
        {"Authorization": "test-ingest-key"},
    ],
)
def test_writes_without_the_key_are_refused(client, headers):
    response = _raw_post(client, headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_forged_clean_audit_cannot_clear_the_posture(client):
    post(client, AUDITOR_PAYLOAD)
    _raw_post(client, {})

    metrics = client.get("/metrics").get_data(as_text=True)
    assert (
        'cloudsentinel_findings_by_severity{provider="aws",severity="CRITICAL"} 1.0'
        in metrics
    )
    assert 'cloudsentinel_ingest_rejected_total{reason="unauthorized"}' in metrics


def test_valid_key_is_accepted(client):
    assert post(client, AUDITOR_PAYLOAD).status_code == 201


def test_ingest_fails_closed_without_a_configured_key(client, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY")
    assert _raw_post(client, {}).status_code == 503


def test_explicit_opt_out_allows_unauthenticated_writes(client, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY")
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_INGEST", "true")
    assert _raw_post(client, {}).status_code == 201


def test_reads_stay_open(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
