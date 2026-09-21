"""
PostgreSQL findings store.

DynamoDB keeps one document per audit, which is right for the dashboard's
audit log but makes cross-audit questions ("which buckets keep showing up?",
"every CRITICAL finding this month") a full-table scan. Each at-risk resource
is therefore also written here as one row, and the /api/findings endpoints
query it.

Configured by DATABASE_URL. When unset - for example in Lambda - the store is
disabled and the API endpoints return 503. DynamoDB stays the source of truth:
a failed write here is logged and counted but does not fail ingestion.

Connections come from a pool. Opening a fresh connection per request (TCP
plus SCRAM authentication) cost more than the queries themselves: pooled,
/api/findings/summary is several times faster under concurrent load.
"""

import logging
import os
import re
from datetime import datetime, timezone

import threading

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

log = logging.getLogger(__name__)

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

_SCHEMA_LOCK_ID = 7_412_001

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    audit_id        TEXT        NOT NULL,
    cloud_provider  TEXT        NOT NULL,
    resource_name   TEXT        NOT NULL,
    severity        TEXT        NOT NULL,
    risk_factors    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    audit_timestamp TIMESTAMPTZ NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity);
CREATE INDEX IF NOT EXISTS findings_resource_idx ON findings (resource_name);
CREATE INDEX IF NOT EXISTS findings_audit_ts_idx ON findings (audit_timestamp DESC);
-- One row per resource per audit, so a redelivered audit cannot inflate the
-- counts. Rows duplicated before the index existed are removed first.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'findings_audit_resource_uidx'
    ) THEN
        DELETE FROM findings a USING findings b
         WHERE a.audit_id = b.audit_id
           AND a.resource_name = b.resource_name
           AND a.id > b.id;
        CREATE UNIQUE INDEX findings_audit_resource_uidx
            ON findings (audit_id, resource_name);
    END IF;
END $$;
"""

_schema_ready = False
_pool = None
_pool_lock = threading.Lock()


def database_url():
    return (os.environ.get("DATABASE_URL") or "").strip() or None


def enabled():
    return database_url() is not None


def reset():
    """Close the pool and forget the schema (tests, config changes)."""
    global _schema_ready, _pool
    _schema_ready = False
    with _pool_lock:
        if _pool is not None:
            _pool.close()
        _pool = None


def get_pool():
    """Per-process pool, opened lazily so each gunicorn worker gets its own."""
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = ConnectionPool(
                database_url(),
                min_size=1,
                max_size=int(os.environ.get("DB_POOL_MAX_SIZE", "10")),
                timeout=5,
                kwargs={"connect_timeout": 3, "row_factory": dict_row},
                check=ConnectionPool.check_connection,
                name="findings",
                open=True,
            )
        return _pool


def _connect():
    return get_pool().connection()


def ensure_schema(conn):
    """Create the table once per process.

    Several gunicorn workers start together; the advisory lock stops their
    concurrent CREATE TABLE IF NOT EXISTS statements from racing.
    """
    global _schema_ready
    if _schema_ready:
        return
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
        conn.execute(_SCHEMA)
    _schema_ready = True


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp; .NET emits 7 fractional digits and 'Z'."""
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def record_findings(audit_id, provider, audit_timestamp, buckets):
    """Insert one row per at-risk resource. Returns the number of rows written."""
    if not buckets:
        return 0
    when = parse_timestamp(audit_timestamp)
    rows = [
        (
            audit_id,
            provider,
            b["BucketName"],
            b["Severity"],
            Jsonb(list(b.get("RiskFactors") or [])),
            when,
        )
        for b in buckets
    ]
    with _connect() as conn:
        ensure_schema(conn)
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO findings (audit_id, cloud_provider, resource_name,"
                " severity, risk_factors, audit_timestamp)"
                " VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (audit_id, resource_name) DO NOTHING",
                rows,
            )
    return len(rows)


def query_findings(severity=None, resource=None, provider=None, limit=100):
    clauses, params = [], []
    if severity:
        clauses.append("severity = %s")
        params.append(severity.upper())
    if resource:
        clauses.append("resource_name = %s")
        params.append(resource)
    if provider:
        clauses.append("cloud_provider = %s")
        params.append(provider)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(int(limit), 1000)))

    with _connect() as conn:
        ensure_schema(conn)
        rows = conn.execute(
            "SELECT audit_id, cloud_provider, resource_name, severity,"
            " risk_factors, audit_timestamp"
            f" FROM findings {where}"
            " ORDER BY audit_timestamp DESC, id DESC LIMIT %s",
            params,
        ).fetchall()

    return [
        {
            "auditId": r["audit_id"],
            "cloudProvider": r["cloud_provider"],
            "resourceName": r["resource_name"],
            "severity": r["severity"],
            "riskFactors": r["risk_factors"],
            "auditTimestamp": r["audit_timestamp"].isoformat(),
        }
        for r in rows
    ]


def summary(top=10):
    """Counts by severity and the resources flagged most often."""
    with _connect() as conn:
        ensure_schema(conn)
        by_severity = {
            r["severity"]: r["count"]
            for r in conn.execute(
                "SELECT severity, count(*) AS count FROM findings GROUP BY severity"
            ).fetchall()
        }
        resources = conn.execute(
            "SELECT resource_name, cloud_provider,"
            " count(DISTINCT audit_id) AS occurrences,"
            " max(audit_timestamp) AS last_seen,"
            " array_agg(DISTINCT severity) AS severities"
            " FROM findings GROUP BY resource_name, cloud_provider"
            " ORDER BY occurrences DESC, last_seen DESC LIMIT %s",
            (top,),
        ).fetchall()

    return {
        "bySeverity": {s: by_severity.get(s, 0) for s in SEVERITY_RANK},
        "topResources": [
            {
                "resourceName": r["resource_name"],
                "cloudProvider": r["cloud_provider"],
                "occurrences": r["occurrences"],
                "lastSeen": r["last_seen"].isoformat(),
                "worstSeverity": max(
                    r["severities"], key=lambda s: SEVERITY_RANK.get(s, 0)
                ),
            }
            for r in resources
        ],
    }
