"""Tamper detection and role policy."""

from __future__ import annotations

import json

import pytest

from pii_proxy.audit import append_event, verify_chain
from pii_proxy.pipeline import run_prompt
from pii_proxy.roles import can_unmask
from pii_proxy.samples import CREDIT_APP


def _append(token: str = "[PII_SSN_00000000-0000-4000-8000-000000000000]"):
    return append_event(
        event="mask",
        actor="jordan.lee",
        role="fi_manager",
        tenant="lakeside-auto-group",
        pii_type="ssn",
        token=token,
    )


def test_verify_chain_empty_is_ok(isolated_data):
    result = verify_chain()
    assert result["ok"] is True
    assert result["entries"] == 0


def test_verify_chain_intact_after_writes(isolated_data):
    run_prompt(CREDIT_APP, actor="jordan.lee", role="fi_manager")
    result = verify_chain()
    assert result["ok"] is True
    assert result["entries"] > 0


def test_tampered_payload_is_detected(isolated_data):
    _append()
    _append("[PII_EMAIL_11111111-1111-4111-8111-111111111111]")
    path = isolated_data / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["actor"] = "intruder"
    lines[0] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_chain()
    assert result["ok"] is False
    assert "entry_hash mismatch" in result["reason"]


def test_broken_prev_hash_is_detected(isolated_data):
    _append()
    _append("[PII_EMAIL_11111111-1111-4111-8111-111111111111]")
    path = isolated_data / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["prev_hash"] = "0" * 64
    # Keep entry_hash as-is so this is a chain-link break, not just a body edit.
    lines[1] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_chain()
    assert result["ok"] is False
    assert "prev_hash mismatch" in result["reason"] or "entry_hash mismatch" in result["reason"]


def test_append_refuses_to_extend_a_tampered_log(isolated_data):
    _append()
    path = isolated_data / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["role"] = "replaced"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="failed verification"):
        _append("[PII_PHONE_22222222-2222-4222-8222-222222222222]")


def test_role_matrix():
    assert can_unmask("fi_manager")
    assert can_unmask("controller")
    assert can_unmask("compliance")
    assert can_unmask("F&I_MANAGER") is False  # must be the id, not a display label
    assert can_unmask("FI_MANAGER")  # case insensitive
    assert not can_unmask("sales_consultant")
    assert not can_unmask("service_advisor")
    assert not can_unmask("")
    assert not can_unmask("admin")  # unknown roles do not unmask
