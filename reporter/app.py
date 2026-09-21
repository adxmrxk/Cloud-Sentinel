"""
CloudSentinel Reporter - Flask API for ingesting findings and serving dashboard
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from decimal import Decimal
from functools import lru_cache

import boto3
from asgiref.wsgi import WsgiToAsgi
from botocore.config import Config
from botocore.exceptions import ClientError
from flask import Flask, Response, g, jsonify, render_template, request
from mangum import Mangum

import cache
import findings_store
import telemetry

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())

app = Flask(__name__)

DEFAULT_PROVIDER = "aws"

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


def send_slack_alert(audit_id, at_risk_buckets, total_scanned):
    """POST a formatted alert to the Slack incoming webhook.

    Returns True if Slack accepted the message, False otherwise.
    Failures are swallowed so a Slack outage cannot break /ingest.
    """
    webhook_url = get_webhook_url()
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
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        app.logger.error(f"Slack webhook failed: {e}")
    telemetry.NOTIFICATIONS.labels("slack", "failed").inc()
    return False


def normalize_bucket(bucket):
    """Accept both key styles.

    The Lambda serializer and the CLI auditor emit camelCase (bucketName);
    the README's example and existing stored audits use PascalCase
    (BucketName). Storage and the dashboard use PascalCase.
    """
    normalized = {
        "BucketName": bucket.get("BucketName") or bucket.get("bucketName") or "unknown",
        "Severity": str(
            bucket.get("Severity") or bucket.get("severity") or "LOW"
        ).upper(),
        "RiskFactors": list(
            bucket.get("RiskFactors") or bucket.get("riskFactors") or []
        ),
    }
    creation_date = bucket.get("CreationDate") or bucket.get("creationDate")
    if creation_date:
        normalized["CreationDate"] = creation_date
    return normalized


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
        audits = load_audits()
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


def load_audits():
    """All audits, newest first. Served from Redis when cached."""
    cached = cache.get_json(cache.AUDITS_KEY)
    if cached is not None:
        return cached

    table = get_table()
    audits = []
    response = table.scan()
    audits.extend(response.get("Items", []))
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        audits.extend(response.get("Items", []))

    audits.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    cache.set_json(cache.AUDITS_KEY, audits)
    return audits


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


@app.route("/ingest", methods=["POST"])
def ingest_findings():
    """
    POST /ingest
    Receives audit findings from Step Functions or the CLI auditor, stores
    them in DynamoDB (and PostgreSQL when configured), refreshes the cache,
    and posts an alert to Slack if any vulnerabilities were found.
    """
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return (
            jsonify({"status": "error", "message": "Body must be a JSON object"}),
            400,
        )

    provider = str(data.get("cloudProvider") or DEFAULT_PROVIDER).lower()

    try:
        audit_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        at_risk_buckets = [
            normalize_bucket(b) for b in data.get("atRiskBuckets", []) or []
        ]
        vulnerabilities_found = bool(data.get("vulnerabilitiesFound", False))
        total_scanned = int(data.get("totalBucketsScanned", 0) or 0)
        audit_timestamp = data.get("auditTimestamp", timestamp)
        scan_duration = data.get("scanDurationSeconds")
        scan_duration = float(scan_duration) if scan_duration is not None else None

        slack_sent = False
        if vulnerabilities_found and at_risk_buckets:
            slack_sent = send_slack_alert(audit_id, at_risk_buckets, total_scanned)

        item = {
            "auditId": audit_id,
            "timestamp": timestamp,
            "cloudProvider": provider,
            "vulnerabilitiesFound": vulnerabilities_found,
            "totalBucketsScanned": total_scanned,
            "atRiskBuckets": at_risk_buckets,
            "auditTimestamp": audit_timestamp,
            "status": "PROCESSED",
            "slackNotified": slack_sent,
        }
        if scan_duration is not None:
            # DynamoDB rejects Python floats; numbers must be Decimal.
            item["scanDurationSeconds"] = Decimal(str(scan_duration))

        get_table().put_item(Item=item)
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

        app.logger.info(f"Stored audit {audit_id} with {len(at_risk_buckets)} findings")

        return (
            jsonify(
                {
                    "status": "success",
                    "auditId": audit_id,
                    "findingsCount": len(at_risk_buckets),
                    "slackNotified": slack_sent,
                    "findingsIndexed": findings_indexed,
                    "message": "Findings ingested successfully",
                }
            ),
            201,
        )

    except Exception as e:
        telemetry.INGEST_ERRORS.labels(provider).inc()
        app.logger.error(f"Ingestion error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/", methods=["GET"])
def dashboard():
    """
    GET /
    Renders HTML dashboard with all audit findings from DynamoDB
    """
    try:
        audits = load_audits()
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return f"<h1>Error</h1><p>{str(e)}</p>", 500

    top_resources = []
    if findings_store.enabled():
        try:
            top_resources = findings_store.summary(top=5)["topResources"]
        except Exception as e:
            app.logger.error(f"Findings store summary failed: {e}")

    return render_template("dashboard.html", audits=audits, top_resources=top_resources)


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
