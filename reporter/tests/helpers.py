import json

README_PAYLOAD = {
    "vulnerabilitiesFound": True,
    "totalBucketsScanned": 12,
    "atRiskBuckets": [
        {
            "BucketName": "demo-bucket",
            "Severity": "CRITICAL",
            "RiskFactors": ["NO_PUBLIC_ACCESS_BLOCK_CONFIGURED"],
        }
    ],
    "auditTimestamp": "2026-01-01T12:00:00Z",
}

# Shape emitted by the auditor Lambda (CamelCaseLambdaJsonSerializer) and CLI.
AUDITOR_PAYLOAD = {
    "vulnerabilitiesFound": True,
    "atRiskBuckets": [
        {
            "bucketName": "open-bucket",
            "creationDate": "2026-09-21T13:29:43.0000000+00:00",
            "riskFactors": ["NO_PUBLIC_ACCESS_BLOCK_CONFIGURED"],
            "severity": "CRITICAL",
        },
        {
            "bucketName": "partial-bucket",
            "creationDate": "2026-09-21T13:29:44.0000000+00:00",
            "riskFactors": [
                "BLOCK_PUBLIC_POLICY_DISABLED",
                "RESTRICT_PUBLIC_BUCKETS_DISABLED",
            ],
            "severity": "MEDIUM",
        },
    ],
    "totalBucketsScanned": 3,
    "auditTimestamp": "2026-09-21T13:30:22.2382719Z",
    "scanDurationSeconds": 0.119,
    "cloudProvider": "aws",
}


def post(client, payload):
    return client.post(
        "/ingest", data=json.dumps(payload), content_type="application/json"
    )


class Ctx:
    aws_request_id = "test-request"


def apigw_event(method, path, body=None, headers=None):
    """API Gateway REST (v1) event, as the state machine now builds it."""
    return {
        "resource": path,
        "path": path,
        "httpMethod": method,
        "headers": headers or {"Content-Type": "application/json", "Host": "x"},
        "multiValueHeaders": {},
        "queryStringParameters": None,
        "multiValueQueryStringParameters": None,
        "pathParameters": None,
        "stageVariables": None,
        "requestContext": {
            "resourcePath": path,
            "httpMethod": method,
            "path": "/Prod" + path,
            "stage": "Prod",
            "protocol": "HTTP/1.1",
            "requestId": "exec-1",
            "identity": {"sourceIp": "0.0.0.0", "userAgent": "AWSStepFunctions"},
        },
        "body": body,
        "isBase64Encoded": False,
    }
