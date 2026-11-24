"""OpenAI-shaped proxy endpoint and role headers."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pii_proxy.api import app
from pii_proxy.samples import CREDIT_APP, SAMPLE_PII


def test_health():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_chat_completions_authorized(isolated_data):
    client = TestClient(app)
    resp = client.post(
        "/v1/chat/completions",
        headers={"X-Role": "fi_manager", "X-Actor": "jordan.lee"},
        json={
            "model": "pii-proxy-mock",
            "messages": [{"role": "user", "content": CREDIT_APP}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    assert SAMPLE_PII["ssn"] in content
    assert SAMPLE_PII["ssn"] not in body["demo"]["masked"]
    assert body["demo"]["unmasked"] is True


def test_chat_completions_unauthorized(isolated_data):
    client = TestClient(app)
    resp = client.post(
        "/v1/chat/completions",
        headers={"X-Role": "sales_consultant", "X-Actor": "alex.nguyen"},
        json={
            "model": "pii-proxy-mock",
            "messages": [{"role": "user", "content": CREDIT_APP}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    assert SAMPLE_PII["ssn"] not in content
    assert body["demo"]["unmasked"] is False
    assert content == body["demo"]["model_output"]


def test_verify_endpoint(isolated_data):
    client = TestClient(app)
    client.post(
        "/v1/proxy",
        json={"prompt": "Call (207) 555-0148", "actor": "j", "role": "fi_manager"},
    )
    resp = client.get("/v1/audit/verify")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["entries"] >= 1
