"""PII detectors for an F&I credit-application style prompt.

These are explainable regex and checksum rules, not a certified DLP or NER
model. They will miss some values and can false-positive. That limitation
is intentional and documented.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from pii_proxy.checks import aba_routing_ok, luhn_ok, vin_ok

# Longer matches win when spans overlap.
PRIORITY = {
    "credit_card": 100,
    "ssn": 90,
    "routing_number": 80,
    "vin": 80,
    "bank_account": 70,
    "email": 70,
    "phone": 60,
    "drivers_license": 55,
    "dob": 50,
    "name": 40,
}

PII_LABELS = {
    "ssn": "SSN",
    "credit_card": "CREDIT_CARD",
    "phone": "PHONE",
    "email": "EMAIL",
    "dob": "DOB",
    "drivers_license": "DL",
    "vin": "VIN",
    "routing_number": "ROUTING",
    "bank_account": "ACCOUNT",
    "name": "NAME",
}


@dataclass(frozen=True)
class Finding:
    pii_type: str
    value: str
    start: int
    end: int
    normalized: str

    def to_dict(self) -> dict:
        return asdict(self)


def _normalize(pii_type: str, value: str) -> str:
    if pii_type in {"ssn", "credit_card", "phone", "routing_number", "bank_account"}:
        return re.sub(r"\D", "", value)
    if pii_type == "email":
        return value.strip().lower()
    if pii_type in {"vin", "drivers_license"}:
        return re.sub(r"[\s-]+", "", value).upper()
    if pii_type == "dob":
        return re.sub(r"\s+", "", value)
    if pii_type == "name":
        return re.sub(r"\s+", " ", value).strip()
    return value.strip()


def _finditer(pattern: str, text: str, flags: int = 0):
    return list(re.finditer(pattern, text, flags))


def _ssns(text: str) -> list[Finding]:
    out: list[Finding] = []
    for match in _finditer(r"\b(\d{3}-\d{2}-\d{4})\b", text):
        out.append(_finding("ssn", match))
    # Bare 9-digit SSNs only when a nearby label makes the intent clear.
    for match in _finditer(
        r"(?i)\b(?:ssn|social\s*security(?:\s*number)?|ss#)\s*[:#]?\s*(\d{9})\b",
        text,
    ):
        group = match.group(1)
        start = match.start(1)
        end = match.end(1)
        out.append(
            Finding("ssn", group, start, end, _normalize("ssn", group))
        )
    return out


# 13–19 digits with optional spaces or dashes. Shared by the card detector
# and by the phone rule, which must not consume a prefix of a card-length run.
_CARD_RUN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# A label immediately before the digits. A mistyped check digit should still
# be treated as a card when the text already calls it one.
_CARD_LABEL = re.compile(
    r"(?i)"
    r"(?:"
    r"\b(?:credit|debit)?\s*cards?(?:\s*(?:number|no\.?|#))?"
    r"|\bcc(?:\s*(?:number|no\.?|#))?"
    r"|\bpan\b"
    r"|\bprimary\s*account\s*number"
    r")"
    r"\s*[:#]?\s*$"
)


def _card_runs(text: str) -> list[tuple[int, int, str, str]]:
    """Return (start, end, raw, digits) for each 13–19 digit card-length run."""
    out: list[tuple[int, int, str, str]] = []
    for match in _CARD_RUN.finditer(text):
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19:
            out.append((match.start(), match.end(), raw.strip(), digits))
    return out


def _preceded_by_card_label(text: str, start: int) -> bool:
    prefix = text[max(0, start - 48) : start]
    return _CARD_LABEL.search(prefix) is not None


def _overlaps_span(start: int, end: int, other_start: int, other_end: int) -> bool:
    return start < other_end and other_start < end


def _cards(text: str) -> list[Finding]:
    out: list[Finding] = []
    for start, end, raw, digits in _card_runs(text):
        # Luhn-valid PANs are always cards. A run that fails Luhn is still a
        # card when a label makes the intent clear, so a typo is masked
        # instead of leaking or being mis-tagged as a phone or account.
        if luhn_ok(digits) or _preceded_by_card_label(text, start):
            out.append(Finding("credit_card", raw, start, end, digits))
    return out


def _phones(text: str) -> list[Finding]:
    out: list[Finding] = []
    card_runs = _card_runs(text)
    pattern = (
        r"(?:(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4})"
    )
    for match in _finditer(pattern, text):
        raw = match.group(0)
        # Avoid treating a SSN-like or other digit run as a phone when it
        # has no separators and is not area-code formatted. Require 10 or 11
        # digits and a typical separator or parentheses if 10+ digits appear.
        digits = re.sub(r"\D", "", raw)
        if len(digits) == 11 and digits.startswith("1"):
            digits = digits[1:]
        if len(digits) != 10:
            continue
        # Reject if this is clearly a dashed SSN (000-00-0000 has two dashes
        # in SSN places) — those are handled by the SSN rule.
        if re.fullmatch(r"\d{3}-\d{2}-\d{4}", raw.strip()):
            continue
        # A 13–19 digit run (with or without separators) is card-length, even
        # when Luhn fails. Do not tag the first 10 digits as a phone.
        if any(_overlaps_span(match.start(), match.end(), s, e) for s, e, _, _ in card_runs):
            continue
        out.append(Finding("phone", raw.strip(), match.start(), match.end(), digits))
    return out


def _emails(text: str) -> list[Finding]:
    out: list[Finding] = []
    for match in _finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        out.append(_finding("email", match))
    return out


def _dobs(text: str) -> list[Finding]:
    out: list[Finding] = []
    # Labeled dates: DOB, date of birth, born
    labeled = (
        r"(?i)\b(?:dob|date\s*of\s*birth|birth(?:day|date)?|born)\s*[:#]?\s*"
        r"("
        r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
        r"|"
        r"\d{4}[/-]\d{1,2}[/-]\d{1,2}"
        r")"
    )
    for match in _finditer(labeled, text):
        start, end = match.start(1), match.end(1)
        value = match.group(1)
        out.append(Finding("dob", value, start, end, _normalize("dob", value)))
    return out


def _licenses(text: str) -> list[Finding]:
    out: list[Finding] = []
    labeled = (
        r"(?i)\b(?:d(?:river'?s?)?\s*l(?:ic(?:en[cs]e)?)?|licen[cs]e(?:\s*no\.?|\s*number)?|dl)\s*[:#]?\s*"
        r"([A-Z]{1,2}\d{4,8}|\d{7,9}|(?:[A-Z]\s*){0,2}\d{3,4}\s*\d{3,4})"
    )
    for match in _finditer(labeled, text):
        start, end = match.start(1), match.end(1)
        value = match.group(1).strip()
        out.append(
            Finding("drivers_license", value, start, end, _normalize("drivers_license", value))
        )
    return out


def _vins(text: str) -> list[Finding]:
    out: list[Finding] = []
    for match in _finditer(r"\b([A-HJ-NPR-Z0-9]{17})\b", text, flags=re.IGNORECASE):
        value = match.group(1)
        if vin_ok(value):
            out.append(
                Finding("vin", value, match.start(), match.end(), value.upper())
            )
    return out


def _routing(text: str) -> list[Finding]:
    out: list[Finding] = []
    labeled = (
        r"(?i)\b(?:routing(?:\s*(?:number|no\.?|#))?|aba(?:\s*#)?)\s*[:#]?\s*"
        r"(\d{9})\b"
    )
    for match in _finditer(labeled, text):
        digits = match.group(1)
        if aba_routing_ok(digits):
            start, end = match.start(1), match.end(1)
            out.append(Finding("routing_number", digits, start, end, digits))
    # Unlabeled 9-digit ABA numbers are easy to confuse with SSNs and ZIPs,
    # so we only accept them with a label.
    return out


def _accounts(text: str) -> list[Finding]:
    out: list[Finding] = []
    labeled = (
        r"(?i)\b(?:bank\s*)?(?:acct|account)(?:\s*(?:number|no\.?|#))?\s*[:#]?\s*"
        r"(\d[0-9 \-]{6,20}\d)"
    )
    for match in _finditer(labeled, text):
        raw = match.group(1).strip()
        digits = re.sub(r"\D", "", raw)
        # 13–19 digit runs are card-length, so they are not bank accounts
        # even when a nearby word is "account" or the number is dashed like a PAN.
        # (The account pattern only allows up to 17 digits, so the remaining
        # window is 8–12.)
        if 8 <= len(digits) <= 12:
            start, end = match.start(1), match.end(1)
            out.append(Finding("bank_account", raw, start, end, digits))
    return out


_NAME_LABEL = (
    r"(?i)\b(?:applicant(?:\s*name)?|customer(?:\s*name)?|borrower(?:\s*name)?|"
    r"full\s*name|name)\s*[:#]\s*"
)
# Two or three capitalized words, optional hyphen/apostrophe.
_NAME_VALUE = r"([A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){1,2})"


def _names(text: str) -> list[Finding]:
    out: list[Finding] = []
    for match in _finditer(_NAME_LABEL + _NAME_VALUE, text):
        value = match.group(1).strip()
        # Skip if it looks like a label continuation.
        if value.lower() in {"date of", "social security"}:
            continue
        start, end = match.start(1), match.end(1)
        out.append(Finding("name", value, start, end, _normalize("name", value)))
    return out


def _finding(pii_type: str, match: re.Match) -> Finding:
    value = match.group(0)
    return Finding(pii_type, value, match.start(), match.end(), _normalize(pii_type, value))


def _overlaps(a: Finding, b: Finding) -> bool:
    return a.start < b.end and b.start < a.end


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Drop overlapping findings, keeping the higher-priority (or longer) span."""
    ordered = sorted(
        findings,
        key=lambda f: (-PRIORITY.get(f.pii_type, 0), -(f.end - f.start), f.start),
    )
    kept: list[Finding] = []
    for item in ordered:
        if any(_overlaps(item, existing) for existing in kept):
            continue
        kept.append(item)
    return sorted(kept, key=lambda f: f.start)


def detect(text: str) -> list[Finding]:
    """Return de-overlapped PII findings in document order."""
    raw = (
        _ssns(text)
        + _cards(text)
        + _phones(text)
        + _emails(text)
        + _dobs(text)
        + _licenses(text)
        + _vins(text)
        + _routing(text)
        + _accounts(text)
        + _names(text)
    )
    return merge_findings(raw)
