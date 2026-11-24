"""Detection coverage, including Luhn, ABA, VIN, and labeled vs unlabeled rules."""

from __future__ import annotations

from pii_proxy.checks import aba_routing_ok, luhn_ok, vin_ok
from pii_proxy.detect import detect
from pii_proxy.samples import CREDIT_APP, SAMPLE_PII


def _types(text: str) -> set[str]:
    return {f.pii_type for f in detect(text)}


def _values(text: str, pii_type: str) -> list[str]:
    return [f.value for f in detect(text) if f.pii_type == pii_type]


def test_luhn_accepts_test_visa():
    assert luhn_ok("4111111111111111")
    assert luhn_ok("4111-1111-1111-1111".replace("-", ""))


def test_luhn_rejects_bad_check_digit():
    assert not luhn_ok("4111111111111112")
    assert not luhn_ok("1234567890123")
    assert not luhn_ok("41111")  # too short


def test_card_detected_only_when_luhn_passes():
    assert _values("Charge 4111-1111-1111-1111 today", "credit_card") == ["4111-1111-1111-1111"]
    assert _values("Charge 4111-1111-1111-1112 today", "credit_card") == []


def test_aba_routing_checksum():
    assert aba_routing_ok("267084005")
    assert not aba_routing_ok("267084006")
    assert not aba_routing_ok("12345678")  # not 9 digits


def test_vin_check_digit():
    assert vin_ok("1LKSDM26XMCB00001")
    assert vin_ok("1HGCM82633A004352")
    assert not vin_ok("1LKSDM260MCB00001")  # wrong check digit
    assert not vin_ok("1LKSDM26IMCB00001")  # I is not a VIN character


def test_ssn_dashed():
    assert _values("SSN 219-09-9999 is on file", "ssn") == ["219-09-9999"]


def test_ssn_bare_only_when_labeled():
    assert _values("The ticket number is 219099999", "ssn") == []
    assert _values("SSN: 219099999", "ssn") == ["219099999"]


def test_phone_and_email():
    assert _values("Call (207) 555-0148 please", "phone") == ["(207) 555-0148"]
    assert _values("Write maya.alvarez@example.com", "email") == ["maya.alvarez@example.com"]


def test_ssn_not_treated_as_phone():
    assert "phone" not in _types("The SSN is 219-09-9999.")


def test_labeled_dob_dl_bank():
    text = (
        "Date of birth: 03/14/1988\n"
        "Driver's license: FL1234567\n"
        "Routing number: 267084005\n"
        "Account number: 1002003344\n"
    )
    assert _values(text, "dob") == ["03/14/1988"]
    assert _values(text, "drivers_license") == ["FL1234567"]
    assert _values(text, "routing_number") == ["267084005"]
    assert _values(text, "bank_account") == ["1002003344"]


def test_unlabeled_routing_is_ignored():
    # A bare 9-digit number should not be treated as a routing number.
    assert _values("The batch id is 267084005 today", "routing_number") == []


def test_name_after_label():
    assert _values("Applicant name: Maya Elena Alvarez\n", "name") == ["Maya Elena Alvarez"]


def test_credit_application_finds_all_sample_types():
    found = {f.pii_type: f.value for f in detect(CREDIT_APP)}
    for key, value in SAMPLE_PII.items():
        assert key in found, f"missing {key}"
        assert found[key] == value


def test_overlaps_prefer_higher_priority():
    # A labeled SSN must not also be captured as something else.
    findings = detect("SSN: 219-09-9999")
    types = [f.pii_type for f in findings]
    assert types.count("ssn") == 1
    assert "phone" not in types
