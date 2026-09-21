"""A redelivered audit (same Idempotency-Key) is stored exactly once."""

import boto3

from tests.helpers import AUDITOR_PAYLOAD, post


def _audits():
    table = boto3.resource("dynamodb", region_name="us-east-1").Table("SecurityAudits")
    return [i for i in table.scan()["Items"] if i.get("recordType") == "AUDIT"]


def test_same_key_is_stored_once(client):
    first = post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-1"})
    again = post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-1"})
    third = post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-1"})

    assert first.status_code == 201
    assert again.status_code == third.status_code == 200
    assert again.get_json()["status"] == "duplicate"
    assert again.get_json()["auditId"] == first.get_json()["auditId"]
    assert len(_audits()) == 1

    totals = client.get("/").get_data(as_text=True)
    assert "Total Audits" in totals


def test_different_keys_are_different_audits(client):
    post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-1"})
    post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-2"})
    assert len(_audits()) == 2


def test_requests_without_a_key_are_not_deduplicated(client):
    post(client, AUDITOR_PAYLOAD)
    post(client, AUDITOR_PAYLOAD)
    assert len(_audits()) == 2


def test_overlong_key_is_rejected(client):
    response = post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "k" * 201})
    assert response.status_code == 400


def _sample(client, prefix):
    metrics = client.get("/metrics").get_data(as_text=True)
    return float(
        next(m for m in metrics.splitlines() if m.startswith(prefix)).split()[-1]
    )


def test_duplicate_does_not_inflate_metrics(client):
    audits = 'cloudsentinel_audits_total{provider="aws",result="vulnerable"}'
    duplicates = 'cloudsentinel_ingest_rejected_total{reason="duplicate"}'
    post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-m"})
    audits_before = _sample(client, audits)
    duplicates_before = _sample(client, duplicates)

    post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-m"})
    post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-m"})

    assert _sample(client, audits) == audits_before
    assert _sample(client, duplicates) == duplicates_before + 2


def test_redelivery_does_not_duplicate_findings_rows(client, postgres):
    for _ in range(3):
        post(client, AUDITOR_PAYLOAD, {"Idempotency-Key": "scan-1"})
    summary = client.get("/api/findings/summary").get_json()
    assert summary["bySeverity"]["CRITICAL"] == 1
    assert summary["topResources"][0]["occurrences"] == 1


def test_findings_store_ignores_a_replayed_write(client, postgres):
    import findings_store

    buckets = [{"BucketName": "b", "Severity": "LOW", "RiskFactors": []}]
    findings_store.record_findings("a1", "aws", None, buckets)
    findings_store.record_findings("a1", "aws", None, buckets)
    assert len(findings_store.query_findings()) == 1
