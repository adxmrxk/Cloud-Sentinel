"""Malformed audits are rejected with 4xx and never stored or crash the API."""

import json

import boto3
import pytest

from tests.helpers import AUTH, README_PAYLOAD

B = {"bucketName": "x", "severity": "LOW"}

MALFORMED = [
    {"vulnerabilitiesFound": True, "atRiskBuckets": "public-assets"},
    {"vulnerabilitiesFound": True, "atRiskBuckets": {"bucketName": "x"}},
    {"vulnerabilitiesFound": True, "atRiskBuckets": ["x"]},
    {"vulnerabilitiesFound": True, "atRiskBuckets": [None]},
    {"totalBucketsScanned": "forty"},
    {"totalBucketsScanned": -5},
    {"totalBucketsScanned": [1]},
    {"totalBucketsScanned": True},
    {"totalBucketsScanned": 1, "atRiskBuckets": [B, B]},
    {"scanDurationSeconds": "fast"},
    {"scanDurationSeconds": -1},
    {"atRiskBuckets": [{"bucketName": "x", "severity": "APOCALYPTIC"}]},
    {"atRiskBuckets": [{"bucketName": "x", "severity": "LOW", "riskFactors": "ABC"}]},
    {"atRiskBuckets": [{"bucketName": "x", "severity": "LOW", "riskFactors": [{}]}]},
    {"atRiskBuckets": [{"bucketName": 123, "severity": "LOW"}]},
    {"atRiskBuckets": [{"bucketName": "a" * 5000, "severity": "LOW"}]},
    {"atRiskBuckets": [{"bucketName": " ", "severity": "LOW"}]},
    {"cloudProvider": {"x": 1}},
    {"cloudProvider": "../../etc"},
    {"vulnerabilitiesFound": "no", "atRiskBuckets": []},
    {"vulnerabilitiesFound": False, "atRiskBuckets": [B]},
    {"auditTimestamp": {"t": 1}},
    {"auditTimestamp": "yesterday"},
    [1, 2, 3],
]


def _stored():
    table = boto3.resource("dynamodb", region_name="us-east-1").Table("SecurityAudits")
    return [i for i in table.scan()["Items"] if i.get("recordType") == "AUDIT"]


def _send(client, body):
    return client.post(
        "/ingest", data=body, content_type="application/json", headers=AUTH
    )


@pytest.mark.parametrize("payload", MALFORMED)
def test_malformed_audit_is_rejected_and_not_stored(client, payload):
    response = _send(client, json.dumps(payload))
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["errors"]
    assert _stored() == []


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_are_rejected(client, constant):
    response = _send(client, '{"scanDurationSeconds": %s}' % constant)
    assert response.status_code == 400


def test_all_problems_are_reported_at_once(client):
    response = _send(
        client,
        json.dumps({"totalBucketsScanned": "x", "cloudProvider": "mars"}),
    )
    assert len(response.get_json()["errors"]) == 2


def test_oversized_body_is_refused_before_parsing(client, monkeypatch):
    import app as reporter_app

    monkeypatch.setitem(reporter_app.app.config, "MAX_CONTENT_LENGTH", 1024)
    big = dict(README_PAYLOAD, padding="x" * 2048)
    assert _send(client, json.dumps(big)).status_code == 413
    assert _stored() == []


def test_valid_payload_still_passes(client):
    assert _send(client, json.dumps(README_PAYLOAD)).status_code == 201


def test_vulnerable_flag_is_derived_when_absent(client):
    payload = {"atRiskBuckets": [B], "totalBucketsScanned": 2}
    assert _send(client, json.dumps(payload)).status_code == 201
    assert _stored()[0]["vulnerabilitiesFound"] is True
