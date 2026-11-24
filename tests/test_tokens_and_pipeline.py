"""Determinism, round-trip restore, no raw PII in model input, role check."""

from __future__ import annotations

from pii_proxy import keys, llm, tokens
from pii_proxy.audit import read_log
from pii_proxy.detect import detect
from pii_proxy.pipeline import run_prompt
from pii_proxy.samples import CREDIT_APP, SAMPLE_PII, all_raw_values


def test_same_value_same_tenant_same_token(isolated_data):
    fernet, secret, _ = keys.ensure_keys()
    a = tokens.token_for("219099999", "ssn", "lakeside-auto-group", secret)
    b = tokens.token_for("219099999", "ssn", "lakeside-auto-group", secret)
    assert a == b
    assert a.startswith("[PII_SSN_")
    assert a.endswith("]")


def test_same_value_different_tenant_different_token(isolated_data):
    _, secret, _ = keys.ensure_keys()
    a = tokens.token_for("219099999", "ssn", "lakeside-auto-group", secret)
    b = tokens.token_for("219099999", "ssn", "northshore-auto-group", secret)
    assert a != b


def test_dashed_and_plain_ssn_normalize_to_same_token(isolated_data):
    _, secret, _ = keys.ensure_keys()
    findings_a = detect("SSN: 219-09-9999")
    findings_b = detect("SSN: 219099999")
    assert findings_a[0].normalized == findings_b[0].normalized == "219099999"
    ta = tokens.token_for(findings_a[0].normalized, "ssn", "t1", secret)
    tb = tokens.token_for(findings_b[0].normalized, "ssn", "t1", secret)
    assert ta == tb


def test_authorized_role_round_trip_restores_values(isolated_data):
    result = run_prompt(CREDIT_APP, actor="jordan.lee", role="fi_manager")
    assert result.unmasked is True
    for value in all_raw_values():
        assert value not in result.masked, f"raw {value!r} leaked into model input"
        assert value not in result.model_output, f"raw {value!r} leaked into model output"
        assert value in result.delivered, f"{value!r} was not restored for the F&I manager"


def test_unauthorized_role_does_not_receive_raw_values(isolated_data):
    result = run_prompt(CREDIT_APP, actor="alex.nguyen", role="sales_consultant")
    assert result.unmasked is False
    assert result.denied_reason
    for value in all_raw_values():
        assert value not in result.masked
        assert value not in result.model_output
        assert value not in result.delivered
    # Tokens are still present so the salesperson can talk about the app without seeing PII.
    assert result.tokens
    for tok in result.tokens:
        assert tok in result.delivered


def test_audit_log_never_contains_raw_pii(isolated_data):
    run_prompt(CREDIT_APP, actor="jordan.lee", role="fi_manager")
    log_text = (isolated_data / "audit.jsonl").read_text(encoding="utf-8")
    for value in all_raw_values():
        assert value not in log_text, f"raw {value!r} appeared in the audit log"
    events = [row["event"] for row in read_log()]
    assert "mask" in events
    assert "unmask" in events


def test_denied_unmask_is_audited(isolated_data):
    run_prompt(CREDIT_APP, actor="alex.nguyen", role="service_advisor")
    events = [row["event"] for row in read_log()]
    assert "mask" in events
    assert "unmask_denied" in events
    assert "unmask" not in events


def test_mock_llm_quotes_tokens_not_raw_values(isolated_data):
    result = run_prompt(CREDIT_APP, actor="jordan.lee", role="fi_manager")
    review = llm.mock_complete(result.masked)
    for tok in result.tokens:
        assert tok in review
    for value in all_raw_values():
        assert value not in review


def test_controller_and_compliance_can_unmask(isolated_data):
    for role in ("controller", "compliance"):
        result = run_prompt(CREDIT_APP, actor="pat.kim", role=role)
        assert result.unmasked is True
        assert SAMPLE_PII["ssn"] in result.delivered
