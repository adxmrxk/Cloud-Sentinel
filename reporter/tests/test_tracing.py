from flask import Flask

import telemetry


def test_tracing_is_off_without_an_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert telemetry.init_tracing(Flask("untraced")) is False


def test_tracing_records_request_spans(monkeypatch):
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
    exporter = InMemorySpanExporter()
    flask_app = Flask("traced")

    @flask_app.route("/ping")
    def ping():
        return "pong"

    enabled = telemetry.init_tracing(
        flask_app, span_exporter=exporter, instrument_libraries=False
    )
    assert enabled is True

    flask_app.test_client().get("/ping")
    spans = exporter.get_finished_spans()
    assert any("/ping" in s.name for s in spans), [s.name for s in spans]
    assert spans[0].resource.attributes["service.name"] == "cloudsentinel-reporter"
