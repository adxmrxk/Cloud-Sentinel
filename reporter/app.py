"""
CloudSentinel Reporter - Flask API for ingesting findings and serving dashboard
"""
import os
import json
import uuid
import urllib.request
import urllib.error
from datetime import datetime
from functools import lru_cache

import boto3
from flask import Flask, request, jsonify, render_template
from mangum import Mangum
from botocore.exceptions import ClientError

app = Flask(__name__)

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityAudits')
SECRET_NAME = os.environ.get('SECRET_NAME', 'CloudSentinel/Config')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
secrets_client = boto3.client('secretsmanager', region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)


@lru_cache(maxsize=1)
def get_secret():
    """Fetch webhook URL from Secrets Manager (cached)"""
    try:
        response = secrets_client.get_secret_value(SecretId=SECRET_NAME)
        secret = json.loads(response['SecretString'])
        return secret
    except ClientError as e:
        app.logger.error(f"Failed to retrieve secret: {e}")
        return {"webhook_url": None}


def get_webhook_url():
    """Resolve the Slack webhook URL. Env var wins over Secrets Manager."""
    env_url = (os.environ.get('SLACK_WEBHOOK_URL') or '').strip()
    if env_url and 'PLACEHOLDER' not in env_url:
        return env_url
    secret_url = (get_secret().get('webhook_url') or '').strip()
    if secret_url and 'PLACEHOLDER' not in secret_url:
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
        return False

    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for bucket in at_risk_buckets:
        sev = bucket.get('Severity', 'LOW')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    top_lines = []
    for bucket in at_risk_buckets[:5]:
        name = bucket.get('BucketName', 'unknown')
        sev = bucket.get('Severity', 'LOW')
        top_lines.append(f"• `{name}`: *{sev}*")
    if len(at_risk_buckets) > 5:
        top_lines.append(f"_...and {len(at_risk_buckets) - 5} more_")

    message = {
        "text": f"CloudSentinel: {len(at_risk_buckets)} S3 bucket(s) at risk",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "CloudSentinel Security Alert"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Audit ID:*\n`{audit_id[:8]}`"},
                    {"type": "mrkdwn", "text": f"*Buckets scanned:*\n{total_scanned}"},
                    {"type": "mrkdwn", "text": f"*At risk:*\n{len(at_risk_buckets)}"},
                    {"type": "mrkdwn", "text": f"*Critical:*\n{severity_counts['CRITICAL']}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Top findings:*\n" + "\n".join(top_lines)}
            }
        ]
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(message).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if 200 <= response.status < 300:
                app.logger.info(f"Slack notified for audit {audit_id}")
                return True
            app.logger.error(f"Slack webhook returned HTTP {response.status}")
            return False
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        app.logger.error(f"Slack webhook failed: {e}")
        return False


@app.route('/ingest', methods=['POST'])
def ingest_findings():
    """
    POST /ingest
    Receives audit findings from Step Functions, stores them in DynamoDB,
    and posts an alert to Slack if any vulnerabilities were found.
    """
    try:
        if request.is_json:
            data = request.get_json()
        else:
            body = request.data.decode('utf-8')
            data = json.loads(body) if body else {}

        audit_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        at_risk_buckets = data.get('atRiskBuckets', [])
        vulnerabilities_found = data.get('vulnerabilitiesFound', False)
        total_scanned = data.get('totalBucketsScanned', 0)

        slack_sent = False
        if vulnerabilities_found and at_risk_buckets:
            slack_sent = send_slack_alert(audit_id, at_risk_buckets, total_scanned)

        item = {
            'auditId': audit_id,
            'timestamp': timestamp,
            'vulnerabilitiesFound': vulnerabilities_found,
            'totalBucketsScanned': total_scanned,
            'atRiskBuckets': at_risk_buckets,
            'auditTimestamp': data.get('auditTimestamp', timestamp),
            'status': 'PROCESSED',
            'slackNotified': slack_sent
        }

        table.put_item(Item=item)

        app.logger.info(f"Stored audit {audit_id} with {len(at_risk_buckets)} findings")

        return jsonify({
            'status': 'success',
            'auditId': audit_id,
            'findingsCount': len(at_risk_buckets),
            'slackNotified': slack_sent,
            'message': 'Findings ingested successfully'
        }), 201

    except Exception as e:
        app.logger.error(f"Ingestion error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/', methods=['GET'])
def dashboard():
    """
    GET /
    Renders HTML dashboard with all audit findings from DynamoDB
    """
    try:
        audits = []
        response = table.scan()
        audits.extend(response.get('Items', []))

        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            audits.extend(response.get('Items', []))

        audits.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return render_template('dashboard.html', audits=audits)

    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return f"<h1>Error</h1><p>{str(e)}</p>", 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'CloudSentinel-Reporter'})


handler = Mangum(app, lifespan="off")
