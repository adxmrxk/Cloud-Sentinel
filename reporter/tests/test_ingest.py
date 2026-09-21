import json

import boto3
import pytest

import app as reporter_app
from tests.helpers import AUDITOR_PAYLOAD, README_PAYLOAD, post


def _items():
    table = boto3.resource("dynamodb", region_name="us-east-1").Table("SecurityAudits")
    return table.scan()["Items"]


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "healthy"


def test_readme_payload_is_stored(client):
    response = post(client, README_PAYLOAD)

    assert response.status_code == 201
    assert response.get_json()["findingsCount"] == 1
    items = _items()
    assert len(items) == 1
    assert items[0]["atRiskBuckets"][0]["BucketName"] == "demo-bucket"
    assert items[0]["cloudProvider"] == "aws"


def test_auditor_camelcase_payload_is_normalized(client):
    response = post(client, AUDITOR_PAYLOAD)

    assert response.status_code == 201
    stored = _items()[0]
    assert [b["BucketName"] for b in stored["atRiskBuckets"]] == [
        "open-bucket",
        "partial-bucket",
    ]
    assert [b["Severity"] for b in stored["atRiskBuckets"]] == ["CRITICAL", "MEDIUM"]
    assert stored["atRiskBuckets"][1]["RiskFactors"] == [
        "BLOCK_PUBLIC_POLICY_DISABLED",
        "RESTRICT_PUBLIC_BUCKETS_DISABLED",
    ]
    # DynamoDB rejects Python floats, so the duration must be stored as Decimal
    assert float(stored["scanDurationSeconds"]) == pytest.approx(0.119)


def test_clean_audit_is_stored_without_findings(client):
    response = post(
        client,
        {"vulnerabilitiesFound": False, "atRiskBuckets": [], "totalBucketsScanned": 4},
    )
    assert response.status_code == 201
    assert response.get_json()["findingsCount"] == 0
    assert _items()[0]["vulnerabilitiesFound"] is False


@pytest.mark.parametrize("body", ["not json", "[1, 2, 3]", ""])
def test_non_object_body_is_rejected(client, body):
    response = client.post("/ingest", data=body, content_type="application/json")
    assert response.status_code == 400


def test_body_without_content_type_is_accepted(client):
    response = client.post("/ingest", data=json.dumps(README_PAYLOAD))
    assert response.status_code == 201


def test_storage_failure_returns_500(client, monkeypatch):
    class Broken:
        def put_item(self, **_):
            raise RuntimeError("dynamodb down")

    monkeypatch.setattr(reporter_app, "get_table", lambda: Broken())
    response = post(client, README_PAYLOAD)
    assert response.status_code == 500
    assert "dynamodb down" in response.get_json()["message"]


def test_dashboard_lists_ingested_audits(client):
    post(client, AUDITOR_PAYLOAD)
    response = client.get("/")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "open-bucket" in html
    assert "CRITICAL" in html


def test_dashboard_empty_state(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "No Audits Yet" in response.get_data(as_text=True)


def test_findings_api_without_database_returns_503(client):
    assert client.get("/api/findings").status_code == 503
    assert client.get("/api/findings/summary").status_code == 503
