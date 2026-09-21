"""
CloudSentinel Reporter - Flask API for ingesting findings and serving dashboard
"""

import base64
import binascii
import hmac
import http.client
import json
import logging
import os
import time
import urllib.request
import uuid
from datetime import datetime
from decimal import Decimal
from functools import lru_cache

import boto3
from asgiref.wsgi import WsgiToAsgi
from boto3.dynamodb.conditions import Key
from botocore.config import Config
from botocore.exceptions import ClientError
from flask import Flask, Response, g, jsonify, render_template, request
from mangum import Mangum

import cache
import findings_store
import notifier
import telemetry
from validation import ValidationError, validate_audit

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())

app = Flask(__name__)

# The largest real audit (10,000 buckets, all at risk) is about 2 MB. Anything
# far beyond that is a mistake or an attack; refuse it before parsing.
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("INGEST_MAX_BYTES", str(5 * 1024 * 1024))
)

DEFAULT_PROVIDER = "aws"

# DynamoDB layout. Audits carry recordType=AUDIT so the byTimestamp index can
# return the newest N with a Query instead of scanning the whole table. One
# STATS item holds running totals for the dashboard header.
AUDIT_RECORD = "AUDIT"
STATS_KEY = {"auditId": "__stats__", "timestamp": "-"}
TIMESTAMP_INDEX = os.environ.get("AUDITS_TIMESTAMP_INDEX", "byTimestamp")
PAGE_SIZE = int(os.environ.get("DASHBOARD_PAGE_SIZE", "25"))

# Idempotency-Key values map onto stable audit IDs, so a redelivered audit
# (Step Functions retry, auditor retry after a lost response) is recognised.
IDEMPOTENCY_NAMESPACE = uuid.UUID("5b2f7c1e-3f0a-4d1c-9b8e-2a6d4c1f0e77")

# botocore defaults to a 60s connect timeout with retries, so an unreachable
# DynamoDB made /ingest hang until gunicorn killed the worker - the client got
# no response and the failure was never counted. Fail fast instead.
AWS_CLIENT_CONFIG = Config(
    connect_timeout=3,
    read_timeout=10,
    retries={"max_attempts": 3, "mode": "standard"},
)


def _env(name, default=None):
    return os.environ.get(name) or default


@lru_cache(maxsize=1)
def get_table():
    """DynamoDB table, created lazily so configuration is read at first use."""
    dynamodb = boto3.resource(
        "dynamodb",
        region_name=_env("AWS_REGION", "us-east-1"),
        endpoint_url=_env("DYNAMODB_ENDPOINT"),
        config=AWS_CLIENT_CONFIG,
    )
    return dynamodb.Table(_env("TABLE_NAME", "SecurityAudits"))


@lru_cache(maxsize=1)
def get_secrets_client():
    return boto3.client(
        "secretsmanager",
        region_name=_env("AWS_REGION", "us-east-1"),
        config=AWS_CLIENT_CONFIG,
    )


@lru_cache(maxsize=1)
def get_secret():
    """Fetch webhook URL from Secrets Manager (cached)"""
    try:
        response = get_secrets_client().get_secret_value(
            SecretId=_env("SECRET_NAME", "CloudSentinel/Config")
        )
        return json.loads(response["SecretString"])
    except ClientError as e:
        app.logger.error(f"Failed to retrieve secret: {e}")
        return {"webhook_url": None}


def get_webhook_url():
    """Resolve the Slack webhook URL. Env var wins over Secrets Manager."""
    env_url = (os.environ.get("SLACK_WEBHOOK_URL") or "").strip()
    if env_url and "PLACEHOLDER" not in env_url:
        return env_url
    secret_url = (get_secret().get("webhook_url") or "").strip()
    if secret_url and "PLACEHOLDER" not in secret_url:
        return secret_url
    return None


def send_slack_alert(audit_id, at_risk_buckets, total_scanned, webhook_url=None):
    """POST a formatted alert to the Slack incoming webhook, once.

    Returns True if Slack accepted the message, False otherwise.
    Failures are swallowed so a Slack outage cannot break /ingest.
    """
    webhook_url = webhook_url or get_webhook_url()
    if not webhook_url:
        app.logger.info("No Slack webhook configured; skipping notification")
        telemetry.NOTIFICATIONS.labels("slack", "skipped").inc()
        return False

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for bucket in at_risk_buckets:
        sev = bucket.get("Severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    top_lines = []
    for bucket in at_risk_buckets[:5]:
        name = bucket.get("BucketName", "unknown")
        sev = bucket.get("Severity", "LOW")
        top_lines.append(f"• `{name}`: *{sev}*")
    if len(at_risk_buckets) > 5:
        top_lines.append(f"_...and {len(at_risk_buckets) - 5} more_")

    message = {
        "text": f"CloudSentinel: {len(at_risk_buckets)} S3 bucket(s) at risk",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "CloudSentinel Security Alert",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Audit ID:*\n`{audit_id[:8]}`"},
                    {"type": "mrkdwn", "text": f"*Buckets scanned:*\n{total_scanned}"},
                    {"type": "mrkdwn", "text": f"*At risk:*\n{len(at_risk_buckets)}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical:*\n{severity_counts['CRITICAL']}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top findings:*\n" + "\n".join(top_lines),
                },
            },
        ],
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(message).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8", errors="replace").strip()
            # Slack answers a delivered webhook message with the literal body
            # "ok". A bare 2xx is not proof: proxies and captive portals return
            # 200 for URLs that never reached Slack.
            if 200 <= response.status < 300 and body == "ok":
                app.logger.info(f"Slack notified for audit {audit_id}")
                telemetry.NOTIFICATIONS.labels("slack", "sent").inc()
                return True
            app.logger.error(
                f"Slack webhook returned HTTP {response.status}: {body[:100]!r}"
            )
    # URLError, timeouts and resets are all OSErrors.
    except (OSError, http.client.HTTPException) as e:
        app.logger.error(f"Slack webhook failed: {e}")
    telemetry.NOTIFICATIONS.labels("slack", "failed").inc()
    return False


def severity_counts(at_risk_buckets):
    counts = {s: 0 for s in telemetry.SEVERITIES}
    for bucket in at_risk_buckets:
        severity = str(bucket.get("Severity", "LOW")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def record_metrics(provider, at_risk_buckets, total_scanned, scan_duration):
    counts = severity_counts(at_risk_buckets)

    telemetry.AUDITS.labels(
        provider, "vulnerable" if at_risk_buckets else "clean"
    ).inc()
    telemetry.RESOURCES_SCANNED.labels(provider, "s3_bucket").inc(total_scanned)
    for severity, count in counts.items():
        telemetry.FINDINGS_BY_SEVERITY.labels(provider, severity).set(count)
        if count:
            telemetry.FINDINGS.labels(provider, severity).inc(count)
    if scan_duration is not None:
        telemetry.SCAN_DURATION.labels(provider).observe(scan_duration)


_posture_restored = False


def restore_posture_gauge():
    """Rebuild the latest-audit gauge from stored audits once per process.

    The gauge lives in process memory, so after a restart or deploy it would
    read "No data" until the next audit arrives - up to a day later. Stored
    audits are the source of truth, so restore it from the newest one per
    provider. Retried on the next scrape if storage is unreachable.
    """
    global _posture_restored
    if _posture_restored:
        return
    try:
        audits, _ = query_audit_page(limit=50)
    except Exception as e:
        app.logger.warning(f"Could not restore posture metrics: {e}")
        return

    latest = {}
    for audit in audits:  # newest first
        latest.setdefault(audit.get("cloudProvider") or DEFAULT_PROVIDER, audit)
    for provider, audit in latest.items():
        counts = severity_counts(audit.get("atRiskBuckets") or [])
        for severity, count in counts.items():
            telemetry.FINDINGS_BY_SEVERITY.labels(provider, severity).set(count)
    _posture_restored = True


# --------------------------------------------------------------------------
# Audit storage
# --------------------------------------------------------------------------


def encode_cursor(last_key):
    if not last_key:
        return None
    raw = json.dumps(last_key, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor):
    """Parse a ?cursor= value; raises ValueError when it was not issued by us."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        key = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        raise ValueError("invalid cursor") from e
    expected = {"auditId", "timestamp", "recordType"}
    if (
        not isinstance(key, dict)
        or set(key) != expected
        or not all(isinstance(v, str) for v in key.values())
        or key["recordType"] != AUDIT_RECORD
    ):
        raise ValueError("invalid cursor")
    return key


def _index_missing(error):
    code = error.response.get("Error", {}).get("Code")
    message = error.response.get("Error", {}).get("Message", "")
    return code in ("ValidationException", "ResourceNotFoundException") and (
        "index" in message.lower()
    )


def _scan_all_audits():
    """Every audit, newest first. Only used before the index exists."""
    table = get_table()
    audits = []
    response = table.scan()
    audits.extend(response.get("Items", []))
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        audits.extend(response.get("Items", []))
    audits = [a for a in audits if a.get("recordType", AUDIT_RECORD) == AUDIT_RECORD]
    audits.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return audits


def query_audit_page(limit=PAGE_SIZE, cursor=None):
    """One page of audits, newest first, and the cursor for the next page.

    The dashboard used to Scan the whole table and render every audit on
    every cache miss - 792 ms and a 6 MB page at 5,000 audits, growing
    linearly. A Query on the byTimestamp index reads only the page shown.
    """
    kwargs = {
        "IndexName": TIMESTAMP_INDEX,
        "KeyConditionExpression": Key("recordType").eq(AUDIT_RECORD),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
    try:
        response = get_table().query(**kwargs)
    except ClientError as e:
        if not _index_missing(e):
            raise
        # Table created before the index was added: stay correct, slowly.
        app.logger.warning(
            f"Index {TIMESTAMP_INDEX} is missing; falling back to a full scan"
        )
        return _scan_all_audits()[:limit], None
    return response.get("Items", []), encode_cursor(response.get("LastEvaluatedKey"))


def empty_stats():
    return {"audits": 0, "bucketsScanned": 0, "findings": 0, "vulnerableAudits": 0}


def rebuild_stats():
    """Recompute the running totals from every audit (one-time migration).

    Also tags audits written before recordType existed so the index sees
    them. Only runs when the STATS item is missing.
    """
    stats = empty_stats()
    table = get_table()
    for audit in _scan_all_audits():
        stats["audits"] += 1
        stats["bucketsScanned"] += int(audit.get("totalBucketsScanned") or 0)
        stats["findings"] += len(audit.get("atRiskBuckets") or [])
        stats["vulnerableAudits"] += 1 if audit.get("vulnerabilitiesFound") else 0
        if audit.get("recordType") != AUDIT_RECORD:
            table.update_item(
                Key={"auditId": audit["auditId"], "timestamp": audit["timestamp"]},
                UpdateExpression="SET recordType = :r",
                ExpressionAttributeValues={":r": AUDIT_RECORD},
            )
    try:
        table.put_item(
            Item={**STATS_KEY, "recordType": "STATS", **stats},
            ConditionExpression="attribute_not_exists(auditId)",
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        return load_stats(rebuild=False)
    return stats


def load_stats(rebuild=True):
    item = get_table().get_item(Key=STATS_KEY).get("Item")
    if item is None:
        return rebuild_stats() if rebuild else empty_stats()
    return {k: int(item.get(k, 0)) for k in empty_stats()}


def add_to_stats(audit):
    get_table().update_item(
        Key=STATS_KEY,
        UpdateExpression=(
            "SET recordType = :t"
            " ADD audits :one, bucketsScanned :scanned, findings :findings,"
            " vulnerableAudits :vulnerable"
        ),
        ExpressionAttributeValues={
            ":t": "STATS",
            ":one": 1,
            ":scanned": audit["totalBucketsScanned"],
            ":findings": len(audit["atRiskBuckets"]),
            ":vulnerable": 1 if audit["vulnerabilitiesFound"] else 0,
        },
    )


def load_dashboard():
    """First dashboard page and the totals. Served from Redis when cached."""
    cached = cache.get_json(cache.AUDITS_KEY)
    if cached is not None:
        return cached
    # Totals first: on a table from before the index, loading them tags the
    # legacy audits so the page query below can see them.
    stats = load_stats()
    audits, next_cursor = query_audit_page()
    view = {"audits": audits, "next": next_cursor, "stats": stats}
    cache.set_json(cache.AUDITS_KEY, view)
    return view


def find_existing_audit(audit_id):
    response = get_table().query(
        KeyConditionExpression=Key("auditId").eq(audit_id), Limit=1
    )
    items = response.get("Items", [])
    return items[0] if items else None


def mark_slack_result(audit_id, timestamp, delivered):
    get_table().update_item(
        Key={"auditId": audit_id, "timestamp": timestamp},
        UpdateExpression="SET slackNotified = :d",
        ExpressionAttributeValues={":d": delivered},
    )
    cache.delete(cache.AUDITS_KEY)


def alert_slack(audit_id, timestamp, at_risk_buckets, total_scanned):
    """Send the Slack alert with retries. Returns "sent", "failed", "skipped" or "queued"."""
    webhook_url = get_webhook_url()
    if not webhook_url:
        telemetry.NOTIFICATIONS.labels("slack", "skipped").inc()
        return "skipped"

    def send_once():
        return send_slack_alert(audit_id, at_risk_buckets, total_scanned, webhook_url)

    if notifier.is_async():
        notifier.submit(
            send_once, lambda ok: mark_slack_result(audit_id, timestamp, ok)
        )
        return "queued"
    return "sent" if notifier.deliver_with_retries(send_once) else "failed"


# --------------------------------------------------------------------------
# Request handling
# --------------------------------------------------------------------------


@app.before_request
def _start_timer():
    g.request_started = time.perf_counter()


@app.after_request
def _record_request(response):
    endpoint = request.url_rule.rule if request.url_rule else "unmatched"
    if endpoint != "/metrics":
        telemetry.API_REQUESTS.labels(
            request.method, endpoint, str(response.status_code)
        ).inc()
        started = getattr(g, "request_started", None)
        if started is not None:
            telemetry.API_LATENCY.labels(request.method, endpoint).observe(
                time.perf_counter() - started
            )
    return response


def _error(status, message, **extra):
    return jsonify({"status": "error", "message": message, **extra}), status


def _truthy(name):
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes")


def check_ingest_auth():
    """Return an error response unless the caller may write audits.

    Anyone who could reach /ingest could post a clean audit and zero every
    CRITICAL gauge and dashboard figure. Writers must now present
    `Authorization: Bearer <INGEST_API_KEY>`. Without a configured key the
    endpoint refuses writes (fail closed), except in Lambda, where the only
    callers are Step Functions (a direct, IAM-authorised invoke) and the
    API Gateway route, which requires IAM auth.
    """
    expected = (os.environ.get("INGEST_API_KEY") or "").strip()
    if not expected:
        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or _truthy(
            "ALLOW_UNAUTHENTICATED_INGEST"
        ):
            return None
        telemetry.INGEST_REJECTED.labels("auth_not_configured").inc()
        return _error(503, "Ingest is disabled until INGEST_API_KEY is configured")

    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        token.strip().encode(), expected.encode()
    ):
        telemetry.INGEST_REJECTED.labels("unauthorized").inc()
        response, status = _error(401, "Missing or invalid API key")
        response.headers["WWW-Authenticate"] = 'Bearer realm="cloudsentinel-ingest"'
        return response, status
    return None


@app.route("/ingest", methods=["POST"])
def ingest_findings():
    """
    POST /ingest
    Receives audit findings from Step Functions or the CLI auditor, stores
    them in DynamoDB (and PostgreSQL when configured), refreshes the cache,
    and alerts Slack if any vulnerabilities were found.

    Headers:
      Authorization: Bearer <INGEST_API_KEY>
      Idempotency-Key: <opaque, <=200 chars>  a redelivery with the same key
                       returns the original audit instead of storing it twice
    """
    denied = check_ingest_auth()
    if denied:
        return denied

    if (request.content_length or 0) > app.config["MAX_CONTENT_LENGTH"]:
        telemetry.INGEST_REJECTED.labels("too_large").inc()
        return _error(413, "Payload too large")

    raw = request.get_data(cache=False)
    try:
        data = json.loads(raw, parse_constant=_reject_constant)
    except ValueError:
        telemetry.INGEST_REJECTED.labels("malformed").inc()
        return _error(400, "Body must be valid JSON")

    try:
        audit = validate_audit(data)
    except ValidationError as e:
        telemetry.INGEST_REJECTED.labels("invalid").inc()
        return _error(422, "Audit payload failed validation", errors=e.errors[:50])

    provider = audit["cloudProvider"]
    idempotency_key = (request.headers.get("Idempotency-Key") or "").strip()
    if len(idempotency_key) > 200:
        return _error(400, "Idempotency-Key must be at most 200 characters")

    try:
        if idempotency_key:
            audit_id = str(uuid.uuid5(IDEMPOTENCY_NAMESPACE, idempotency_key))
            existing = find_existing_audit(audit_id)
            if existing is not None:
                telemetry.INGEST_REJECTED.labels("duplicate").inc()
                app.logger.info(f"Duplicate delivery of audit {audit_id} ignored")
                return (
                    jsonify(
                        {
                            "status": "duplicate",
                            "auditId": audit_id,
                            "findingsCount": len(existing.get("atRiskBuckets") or []),
                            "message": "Audit already ingested",
                        }
                    ),
                    200,
                )
        else:
            audit_id = str(uuid.uuid4())

        timestamp = datetime.utcnow().isoformat()
        at_risk_buckets = audit["atRiskBuckets"]
        total_scanned = audit["totalBucketsScanned"]
        audit_timestamp = audit["auditTimestamp"] or timestamp
        scan_duration = audit["scanDurationSeconds"]

        item = {
            "auditId": audit_id,
            "timestamp": timestamp,
            "recordType": AUDIT_RECORD,
            "cloudProvider": provider,
            "vulnerabilitiesFound": audit["vulnerabilitiesFound"],
            "totalBucketsScanned": total_scanned,
            "atRiskBuckets": at_risk_buckets,
            "auditTimestamp": audit_timestamp,
            "status": "PROCESSED",
            "slackNotified": False,
        }
        if scan_duration is not None:
            # DynamoDB rejects Python floats; numbers must be Decimal.
            item["scanDurationSeconds"] = Decimal(str(scan_duration))

        get_table().put_item(Item=item)
        try:
            add_to_stats(audit)
        except Exception as e:  # totals are a convenience; the audit is stored
            app.logger.error(f"Updating dashboard totals failed: {e}")
        cache.delete(cache.AUDITS_KEY)

        findings_indexed = False
        if findings_store.enabled():
            try:
                findings_store.record_findings(
                    audit_id, provider, audit_timestamp, at_risk_buckets
                )
                findings_indexed = True
                telemetry.FINDINGS_STORE_WRITES.labels("ok").inc()
            except Exception as e:
                telemetry.FINDINGS_STORE_WRITES.labels("error").inc()
                app.logger.error(f"Findings store write failed: {e}")

        record_metrics(provider, at_risk_buckets, total_scanned, scan_duration)

        slack = "not_needed"
        if at_risk_buckets:
            slack = alert_slack(audit_id, timestamp, at_risk_buckets, total_scanned)
            if slack in ("sent", "failed"):
                mark_slack_result(audit_id, timestamp, slack == "sent")

        app.logger.info(f"Stored audit {audit_id} with {len(at_risk_buckets)} findings")

        return (
            jsonify(
                {
                    "status": "success",
                    "auditId": audit_id,
                    "findingsCount": len(at_risk_buckets),
                    "slackNotified": slack == "sent",
                    "slackNotification": slack,
                    "findingsIndexed": findings_indexed,
                    "message": "Findings ingested successfully",
                }
            ),
            201,
        )

    except Exception as e:
        telemetry.INGEST_ERRORS.labels(provider).inc()
        app.logger.error(f"Ingestion error: {str(e)}")
        return _error(500, "Internal error while storing the audit")


def _reject_constant(name):
    raise ValueError(f"{name} is not valid JSON")


@app.route("/", methods=["GET"])
def dashboard():
    """
    GET /?cursor=<opaque>
    Renders the HTML dashboard: running totals plus one page of audits.
    """
    cursor = request.args.get("cursor")
    try:
        if cursor:
            stats = load_stats()
            audits, next_cursor = query_audit_page(cursor=cursor)
            view = {"audits": audits, "next": next_cursor, "stats": stats}
        else:
            view = load_dashboard()
    except ValueError:
        return "<h1>Bad request</h1><p>Invalid page cursor.</p>", 400
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return "<h1>Error</h1><p>The audit store is unavailable.</p>", 500

    top_resources = []
    if findings_store.enabled():
        try:
            top_resources = findings_store.summary(top=5)["topResources"]
        except Exception as e:
            app.logger.error(f"Findings store summary failed: {e}")

    return render_template(
        "dashboard.html",
        audits=view["audits"],
        stats=view["stats"],
        next_cursor=view["next"],
        paged=bool(cursor),
        top_resources=top_resources,
    )


@app.route("/api/audits", methods=["GET"])
def list_audits():
    """
    GET /api/audits?limit=25&cursor=<opaque>
    Audits newest first, one page at a time.
    """
    try:
        limit = max(1, min(int(request.args.get("limit", PAGE_SIZE)), 100))
        audits, next_cursor = query_audit_page(
            limit=limit, cursor=request.args.get("cursor")
        )
    except ValueError:
        return _error(400, "limit must be an integer and cursor must be valid")
    except Exception as e:
        app.logger.error(f"Audit listing failed: {e}")
        return _error(500, "The audit store is unavailable")
    return jsonify(
        {
            "audits": json.loads(json.dumps(audits, default=cache._to_json)),
            "next": next_cursor,
        }
    )


def _findings_store_unavailable():
    return (
        jsonify(
            {
                "status": "error",
                "message": "Findings store is not configured (set DATABASE_URL)",
            }
        ),
        503,
    )


@app.route("/api/findings", methods=["GET"])
def list_findings():
    """
    GET /api/findings?severity=CRITICAL&resource=my-bucket&provider=aws&limit=100
    Individual findings across all audits, newest first.
    """
    if not findings_store.enabled():
        return _findings_store_unavailable()
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        return jsonify({"status": "error", "message": "limit must be an integer"}), 400
    try:
        findings = findings_store.query_findings(
            severity=request.args.get("severity"),
            resource=request.args.get("resource"),
            provider=request.args.get("provider"),
            limit=limit,
        )
    except Exception as e:
        app.logger.error(f"Findings query failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"findings": findings, "count": len(findings)})


@app.route("/api/findings/summary", methods=["GET"])
def findings_summary():
    """
    GET /api/findings/summary
    Finding counts by severity and the resources flagged most often.
    """
    if not findings_store.enabled():
        return _findings_store_unavailable()
    try:
        return jsonify(findings_store.summary())
    except Exception as e:
        app.logger.error(f"Findings summary failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus scrape endpoint"""
    restore_posture_gauge()
    body, content_type = telemetry.metrics_payload()
    return Response(body, mimetype=content_type)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "CloudSentinel-Reporter"})


telemetry.init_tracing(app)


class EnsureContentLength:
    """ASGI shim that supplies a missing Content-Length header.

    Mangum builds the ASGI scope directly from the Lambda event. API Gateway
    always sends Content-Length, but a caller that constructs the event itself
    (the Step Functions state machine does exactly this) does not. Without the
    header the WSGI layer reports an empty body and Flask rejects the request
    as malformed, so derive it from the body when it is absent.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = list(scope.get("headers") or [])
        if any(name == b"content-length" for name, _ in headers):
            await self.app(scope, receive, send)
            return

        chunks = []
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)
        body = b"".join(chunks)

        scope = dict(scope)
        scope["headers"] = headers + [
            (b"content-length", str(len(body)).encode("latin-1"))
        ]

        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


# Mangum is an ASGI adapter and Flask is a WSGI application, so the app has to
# be bridged to ASGI before Mangum can drive it. Passing the Flask object
# straight to Mangum raises TypeError on every invocation.
handler = Mangum(EnsureContentLength(WsgiToAsgi(app)), lifespan="off")
