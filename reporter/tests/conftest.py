import os
import sys

import boto3
import fakeredis
import pytest
from moto import mock_aws

REPORTER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPORTER_DIR)

# Configure before the app module is imported anywhere.
os.environ.update(
    {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1",
        "TABLE_NAME": "SecurityAudits",
        "SECRET_NAME": "CloudSentinel/Config",
    }
)
for var in (
    "DYNAMODB_ENDPOINT",
    "SLACK_WEBHOOK_URL",
    "REDIS_URL",
    "REDIS_HOST",
    "DATABASE_URL",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "PROMETHEUS_MULTIPROC_DIR",
):
    os.environ.pop(var, None)

import app as reporter_app  # noqa: E402
import cache  # noqa: E402
import findings_store  # noqa: E402


def _clear_caches():
    reporter_app.get_table.cache_clear()
    reporter_app.get_secrets_client.cache_clear()
    reporter_app.get_secret.cache_clear()
    cache.reset()
    findings_store.reset()


@pytest.fixture
def aws():
    """Mocked DynamoDB table and Secrets Manager secret."""
    with mock_aws():
        _clear_caches()
        dynamodb = boto3.client("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="SecurityAudits",
            AttributeDefinitions=[
                {"AttributeName": "auditId", "AttributeType": "S"},
                {"AttributeName": "timestamp", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "auditId", "KeyType": "HASH"},
                {"AttributeName": "timestamp", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        boto3.client("secretsmanager", region_name="us-east-1").create_secret(
            Name="CloudSentinel/Config",
            SecretString='{"webhook_url": "https://hooks.slack.com/services/PLACEHOLDER"}',
        )
        yield
        _clear_caches()


@pytest.fixture
def client(aws, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    reporter_app.app.config["TESTING"] = True
    with reporter_app.app.test_client() as c:
        yield c


@pytest.fixture
def redis_cache(monkeypatch):
    fake = fakeredis.FakeRedis()
    monkeypatch.setattr(cache, "_client", fake)
    return fake


@pytest.fixture
def postgres(monkeypatch):
    """Real PostgreSQL; tests using it are skipped unless TEST_DATABASE_URL is set."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    import psycopg

    monkeypatch.setenv("DATABASE_URL", url)
    findings_store.reset()
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS findings")
    yield url
    findings_store.reset()
