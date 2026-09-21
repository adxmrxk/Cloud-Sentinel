"""Findings store tests. Those using the `postgres` fixture need TEST_DATABASE_URL."""

from datetime import timezone

import findings_store
from tests.helpers import AUDITOR_PAYLOAD, README_PAYLOAD, post


def test_ingest_writes_one_row_per_finding(client, postgres):
    response = post(client, AUDITOR_PAYLOAD)
    assert response.get_json()["findingsIndexed"] is True

    findings = client.get("/api/findings").get_json()["findings"]
    assert {f["resourceName"] for f in findings} == {"open-bucket", "partial-bucket"}
    assert findings[0]["cloudProvider"] == "aws"


def test_filters(client, postgres):
    post(client, AUDITOR_PAYLOAD)
    post(client, README_PAYLOAD)

    critical = client.get("/api/findings?severity=critical").get_json()["findings"]
    assert {f["resourceName"] for f in critical} == {"open-bucket", "demo-bucket"}

    one = client.get("/api/findings?resource=partial-bucket").get_json()["findings"]
    assert [f["severity"] for f in one] == ["MEDIUM"]

    assert client.get("/api/findings?limit=1").get_json()["count"] == 1
    assert client.get("/api/findings?limit=abc").status_code == 400


def test_summary_ranks_repeat_offenders(client, postgres):
    post(client, AUDITOR_PAYLOAD)
    post(client, AUDITOR_PAYLOAD)
    post(client, README_PAYLOAD)

    summary = client.get("/api/findings/summary").get_json()
    assert summary["bySeverity"] == {"CRITICAL": 3, "HIGH": 0, "MEDIUM": 2, "LOW": 0}
    top = summary["topResources"][0]
    assert top["occurrences"] == 2
    assert top["resourceName"] in {"open-bucket", "partial-bucket"}


def test_dashboard_shows_repeat_offenders(client, postgres):
    post(client, AUDITOR_PAYLOAD)
    assert "Repeat Offenders" in client.get("/").get_data(as_text=True)


def test_database_outage_does_not_fail_ingest(client, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://nobody:nothing@127.0.0.1:1/none")
    findings_store.reset()
    response = post(client, AUDITOR_PAYLOAD)
    assert response.status_code == 201
    assert response.get_json()["findingsIndexed"] is False


def test_dotnet_timestamps_are_parsed():
    parsed = findings_store.parse_timestamp("2026-09-21T13:30:22.2382719Z")
    assert parsed.tzinfo == timezone.utc
    assert (parsed.year, parsed.microsecond) == (2026, 238271)
    assert findings_store.parse_timestamp("garbage").tzinfo is not None
