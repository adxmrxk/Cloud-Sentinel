"""The dashboard reads one indexed page, not the whole table."""

import re
import uuid

import boto3
from moto import mock_aws

import app as reporter_app
from tests.conftest import _clear_caches, create_audits_table
from tests.helpers import README_PAYLOAD, post


def _table():
    return boto3.resource("dynamodb", region_name="us-east-1").Table("SecurityAudits")


def _stat(html, label):
    match = re.search(
        r'stat-value">\s*(\d+)\s*</div>\s*<div class="stat-label">' + label, html
    )
    return int(match.group(1))


def _rows(html):
    return len(re.findall(r'class="audit-id"', html))


def test_dashboard_renders_one_page_with_full_totals(client, monkeypatch):
    for _ in range(30):
        post(client, README_PAYLOAD)

    def no_scan(**_):
        raise AssertionError("dashboard scanned the whole table")

    monkeypatch.setattr(reporter_app.get_table(), "scan", no_scan)
    html = client.get("/").get_data(as_text=True)

    assert _rows(html) == reporter_app.PAGE_SIZE == 25
    assert _stat(html, "Total Audits") == 30
    assert _stat(html, "Buckets Scanned") == 30 * 12
    assert _stat(html, "Total Findings") == 30
    assert "Older audits" in html


def test_cursor_walks_every_audit_once_newest_first(client):
    for _ in range(7):
        post(client, README_PAYLOAD)

    seen, cursor = [], None
    while True:
        url = "/api/audits?limit=3" + (f"&cursor={cursor}" if cursor else "")
        page = client.get(url).get_json()
        seen.extend((a["timestamp"], a["auditId"]) for a in page["audits"])
        cursor = page["next"]
        if not cursor:
            break

    assert len(seen) == len(set(seen)) == 7
    timestamps = [t for t, _ in seen]
    assert timestamps == sorted(timestamps, reverse=True)


def test_second_dashboard_page(client):
    for _ in range(30):
        post(client, README_PAYLOAD)
    first = client.get("/api/audits?limit=25").get_json()
    html = client.get(f"/?cursor={first['next']}").get_data(as_text=True)
    assert _rows(html) == 5
    assert "Newest audits" in html


def test_forged_cursor_is_rejected(client):
    assert client.get("/?cursor=not-a-cursor").status_code == 400
    assert client.get("/api/audits?cursor=e30").status_code == 400


def test_legacy_audits_are_migrated_on_first_read(client):
    # Written before recordType and the STATS item existed.
    table = _table()
    for i in range(3):
        table.put_item(
            Item={
                "auditId": str(uuid.uuid4()),
                "timestamp": f"2026-01-0{i + 1}T00:00:00",
                "totalBucketsScanned": 4,
                "vulnerabilitiesFound": i == 0,
                "atRiskBuckets": (
                    [{"BucketName": "old", "Severity": "HIGH", "RiskFactors": []}]
                    if i == 0
                    else []
                ),
            }
        )

    html = client.get("/").get_data(as_text=True)
    assert _stat(html, "Total Audits") == 3
    assert _stat(html, "Buckets Scanned") == 12
    assert _stat(html, "Audits with Issues") == 1
    assert _rows(html) == 3

    # Later ingests add to the rebuilt totals.
    post(client, README_PAYLOAD)
    assert _stat(client.get("/").get_data(as_text=True), "Total Audits") == 4


def test_table_without_index_falls_back_to_scan(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with mock_aws():
        _clear_caches()
        create_audits_table(with_index=False)
        boto3.client("secretsmanager", region_name="us-east-1").create_secret(
            Name="CloudSentinel/Config", SecretString="{}"
        )
        client = reporter_app.app.test_client()
        post(client, README_PAYLOAD)
        html = client.get("/").get_data(as_text=True)
        assert _rows(html) == 1
        _clear_caches()
