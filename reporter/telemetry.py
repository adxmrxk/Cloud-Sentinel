"""
Prometheus metrics and OpenTelemetry tracing for the reporter.

Metrics work in three modes:
- gunicorn (container): PROMETHEUS_MULTIPROC_DIR is set by gunicorn.conf.py so
  every worker writes to a shared directory and /metrics aggregates them.
  Without this each scrape would only see whichever worker answered it.
- Lambda and tests: the default in-process registry.

Tracing is enabled only when OTEL_EXPORTER_OTLP_ENDPOINT is set, e.g.
http://jaeger:4318 in the Compose stack.
"""

import logging
import os

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)

log = logging.getLogger(__name__)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

API_REQUESTS = Counter(
    "cloudsentinel_api_requests",
    "HTTP requests served by the reporter",
    ["method", "endpoint", "status"],
)
API_LATENCY = Histogram(
    "cloudsentinel_api_request_duration_seconds",
    "Reporter request latency",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
AUDITS = Counter(
    "cloudsentinel_audits",
    "Audits ingested, by outcome",
    ["provider", "result"],
)
FINDINGS = Counter(
    "cloudsentinel_findings",
    "At-risk resources reported across all audits",
    ["provider", "severity"],
)
FINDINGS_BY_SEVERITY = Gauge(
    "cloudsentinel_findings_by_severity",
    "At-risk resources in the most recent audit",
    ["provider", "severity"],
    multiprocess_mode="mostrecent",
)
RESOURCES_SCANNED = Counter(
    "cloudsentinel_resources_scanned",
    "Resources inspected by auditors",
    ["provider", "resource_type"],
)
SCAN_DURATION = Histogram(
    "cloudsentinel_scan_duration_seconds",
    "Wall-clock duration of an audit, as reported by the auditor",
    ["provider"],
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600),
)
INGEST_ERRORS = Counter(
    "cloudsentinel_ingest_errors",
    "Audit payloads the reporter failed to process",
    ["provider"],
)
NOTIFICATIONS = Counter(
    "cloudsentinel_notifications",
    "Alert delivery attempts",
    ["channel", "result"],
)
CACHE_OPERATIONS = Counter(
    "cloudsentinel_cache_operations",
    "Redis cache operations",
    ["operation", "result"],
)
FINDINGS_STORE_WRITES = Counter(
    "cloudsentinel_findings_store_writes",
    "Writes of findings to the PostgreSQL findings store",
    ["result"],
)

# Export zero-valued series up front so error panels read 0 instead of
# "No data" before the first failure happens.
for _provider in ("aws",):
    INGEST_ERRORS.labels(_provider)


def metrics_payload():
    """Return (body, content_type) for the /metrics endpoint."""
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry), CONTENT_TYPE_LATEST
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def init_tracing(flask_app, span_exporter=None, instrument_libraries=True):
    """Install OpenTelemetry tracing if an OTLP endpoint is configured.

    span_exporter and instrument_libraries exist for tests, which export to
    memory and must not patch botocore/redis/psycopg process-wide.
    Returns True when tracing was enabled.
    """
    endpoint = (os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or "").strip()
    if not endpoint:
        return False

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.instrumentation.urllib import URLLibInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

    service_name = os.environ.get("OTEL_SERVICE_NAME", "cloudsentinel-reporter")
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    if span_exporter is None:
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=endpoint.rstrip("/") + "/v1/traces")
            )
        )
    else:
        provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    trace.set_tracer_provider(provider)

    FlaskInstrumentor().instrument_app(
        flask_app, excluded_urls="health,metrics", tracer_provider=provider
    )
    if instrument_libraries:
        BotocoreInstrumentor().instrument()
        RedisInstrumentor().instrument()
        PsycopgInstrumentor().instrument()
        URLLibInstrumentor().instrument()

    log.info("OpenTelemetry tracing enabled, exporting to %s", endpoint)
    return True
