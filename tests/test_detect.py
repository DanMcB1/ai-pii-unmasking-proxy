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
    # All-numeric 17-digit runs can pass the check digit (all nines does)
    # but are not VINs, because a real VIN always contains letters.
    assert not vin_ok("99999999999999999")


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

def test_failed_luhn_card_run_is_not_phone_or_account():
    # 16 digits that fail Luhn used to be tagged as a phone (first 10 digits,
    # offsets 12–22) when they followed a card label.
    plain = "Card number 4111111111111112 for a $200 deposit"
    findings = detect(plain)
    types = [f.pii_type for f in findings]
    assert "phone" not in types
    assert "bank_account" not in types
    assert _values(plain, "credit_card") == ["4111111111111112"]
    card = next(f for f in findings if f.pii_type == "credit_card")
    assert (card.start, card.end) == (12, 28)

    # The dashed form used to be tagged as a bank account. After a card label
    # it is a card; after an account label it is left untagged (Luhn fails,
    # and card-length runs are not accounts).
    dashed_card = "Card number 4111-1111-1111-1112 for a $200 deposit"
    assert "phone" not in _types(dashed_card)
    assert "bank_account" not in _types(dashed_card)
    assert _values(dashed_card, "credit_card") == ["4111-1111-1111-1112"]

    dashed_account = "Account number: 4111-1111-1111-1112"
    assert _values(dashed_account, "bank_account") == []
    assert _values(dashed_account, "credit_card") == []
    assert "phone" not in _types(dashed_account)

    # Unlabeled failed-Luhn runs stay untagged, and are still not phones.
    unlabeled = "Charge 4111111111111112 today"
    assert _types(unlabeled) == set()


def test_real_phone_and_account_still_detected():
    assert _values("Call (207) 555-0148 please", "phone") == ["(207) 555-0148"]
    assert _values("Mobile 207-555-0148", "phone") == ["207-555-0148"]
    assert _values("Account number: 1002003344", "bank_account") == ["1002003344"]

def test_numeric_17_digit_run_is_not_a_vin():
    # A pure-numeric 17-digit run that happens to pass the VIN check digit
    # used to be tagged as a VIN. It should follow the 13-19 digit rule.
    nines = "99999999999999999"
    unlabeled = f"The reference number is {nines} today"
    assert vin_ok("1HGCM82633A004352")
    assert _values("VIN 1HGCM82633A004352 is on the lot", "vin") == ["1HGCM82633A004352"]
    assert "vin" not in _types(unlabeled)
    assert "phone" not in _types(unlabeled)
    assert "bank_account" not in _types(unlabeled)
    assert _values(unlabeled, "credit_card") == []

    # Luhn-valid 17-digit numeric runs are cards, not VINs.
    luhn_ok_17 = "99999999999999996"
    assert luhn_ok(luhn_ok_17)
    assert _values(f"Charge {luhn_ok_17} today", "credit_card") == [luhn_ok_17]
    assert "vin" not in _types(f"Charge {luhn_ok_17} today")

    # After a card label, a 17-digit run that fails Luhn is still a card.
    labeled = f"Card number {nines} for a deposit"
    assert _values(labeled, "credit_card") == [nines]
    assert "vin" not in _types(labeled)
    assert "phone" not in _types(labeled)
    assert "bank_account" not in _types(labeled)

    # After an account label, the same failed-Luhn run stays untagged.
    account = f"Account number: {nines}"
    assert _types(account) == set()
