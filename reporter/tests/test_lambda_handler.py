"""The Step Functions -> Reporter Lambda contract, driven from the real ASL file."""

import copy
import json
import os

import pytest

import app as reporter_app
from tests.helpers import AUDITOR_PAYLOAD, Ctx, apigw_event

ASL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "statemachine", "audit-workflow.asl.json"
)


@pytest.fixture(autouse=True)
def in_lambda(monkeypatch):
    """Lambda: no API key; callers are IAM-authorised (Step Functions, API GW)."""
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "CloudSentinel-Reporter")


def _load_asl():
    with open(ASL_PATH, encoding="utf-8") as f:
        return json.load(f)


def _resolve(template, audit_result):
    """Render a Step Functions Parameters block the way the service would."""
    if isinstance(template, dict):
        out = {}
        for key, value in template.items():
            if key.endswith(".$"):
                name = key[:-2]
                if value == "States.JsonToString($.auditResult)":
                    out[name] = json.dumps(audit_result)
                elif value == "$$.Execution.Name":
                    out[name] = "execution-123"
                else:
                    raise AssertionError(f"unhandled path expression {value}")
            else:
                out[key] = _resolve(value, audit_result)
        return out
    if isinstance(template, list):
        return [_resolve(v, audit_result) for v in template]
    return template


def test_state_machine_payload_reaches_ingest(aws):
    payload_template = _load_asl()["States"]["ProcessFindings"]["Parameters"]["Payload"]
    event = _resolve(copy.deepcopy(payload_template), AUDITOR_PAYLOAD)

    response = reporter_app.handler(event, Ctx())

    assert response["statusCode"] == 201, response["body"]
    assert json.loads(response["body"])["findingsCount"] == 2

    # A Step Functions retry of the same execution is not stored twice.
    retry = reporter_app.handler(event, Ctx())
    assert retry["statusCode"] == 200, retry["body"]
    assert json.loads(retry["body"])["status"] == "duplicate"


def test_process_findings_is_retried_on_transient_lambda_errors():
    retry = _load_asl()["States"]["ProcessFindings"]["Retry"]
    errors = {e for r in retry for e in r["ErrorEquals"]}
    assert "Lambda.ServiceException" in errors
    assert "Lambda.TooManyRequestsException" in errors


def test_result_selector_forwards_every_field_the_reporter_reads():
    selector = _load_asl()["States"]["RunAuditor"]["ResultSelector"]
    forwarded = {key[:-2] for key in selector}
    assert forwarded >= {
        "vulnerabilitiesFound",
        "atRiskBuckets",
        "totalBucketsScanned",
        "auditTimestamp",
        "scanDurationSeconds",
        "cloudProvider",
    }


def test_api_gateway_dashboard_route(aws):
    response = reporter_app.handler(apigw_event("GET", "/"), Ctx())
    assert response["statusCode"] == 200
    assert "CloudSentinel Dashboard" in response["body"]


def test_api_gateway_ingest_with_content_length(aws):
    body = json.dumps(AUDITOR_PAYLOAD)
    event = apigw_event(
        "POST",
        "/ingest",
        body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    response = reporter_app.handler(event, Ctx())
    assert response["statusCode"] == 201


def _walk(asl, vulnerabilities_found):
    """Follow the state machine the way Step Functions would for one audit."""
    state_input = {"auditResult": {"vulnerabilitiesFound": vulnerabilities_found}}
    name, path = asl["StartAt"], []
    while True:
        path.append(name)
        state = asl["States"][name]
        if state["Type"] in ("Succeed", "Fail"):
            return path
        if state["Type"] == "Choice":
            name = state["Default"]
            for choice in state["Choices"]:
                assert choice["Variable"] == "$.auditResult.vulnerabilitiesFound"
                if (
                    state_input["auditResult"]["vulnerabilitiesFound"]
                    == choice["BooleanEquals"]
                ):
                    name = choice["Next"]
                    break
        else:
            name = state["Next"]


def test_clean_audits_are_recorded_without_alerting():
    path = _walk(_load_asl(), vulnerabilities_found=False)
    assert "ProcessFindings" in path
    assert "SendAlert" not in path
    assert path[-1] == "AuditComplete"


def test_vulnerable_audits_are_recorded_then_alerted():
    path = _walk(_load_asl(), vulnerabilities_found=True)
    assert path.index("ProcessFindings") < path.index("SendAlert")
    assert path[-1] == "AuditComplete"
