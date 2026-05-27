"""
CloudSentinel Reporter - Flask API for ingesting findings and serving dashboard
"""
import os
import json
import uuid
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


@app.route('/ingest', methods=['POST'])
def ingest_findings():
    """
    POST /ingest
    Receives audit findings from Step Functions and stores in DynamoDB
    """
    try:
        if request.is_json:
            data = request.get_json()
        else:
            body = request.data.decode('utf-8')
            data = json.loads(body) if body else {}

        audit_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        secrets = get_secret()
        webhook_url = secrets.get('webhook_url')

        item = {
            'auditId': audit_id,
            'timestamp': timestamp,
            'vulnerabilitiesFound': data.get('vulnerabilitiesFound', False),
            'totalBucketsScanned': data.get('totalBucketsScanned', 0),
            'atRiskBuckets': data.get('atRiskBuckets', []),
            'auditTimestamp': data.get('auditTimestamp', timestamp),
            'status': 'PROCESSED',
            'webhookNotified': webhook_url is not None
        }

        table.put_item(Item=item)

        app.logger.info(f"Stored audit {audit_id} with {len(item['atRiskBuckets'])} findings")

        return jsonify({
            'status': 'success',
            'auditId': audit_id,
            'findingsCount': len(item['atRiskBuckets']),
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
