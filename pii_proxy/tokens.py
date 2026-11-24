"""Deterministic, tenant-scoped tokens derived with HMAC-SHA256.

The same raw value + type + tenant always yields the same token. A
different tenant gets a different token for the same raw value, so two
stores cannot compare tokens to join customer records.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid

from pii_proxy.detect import PII_LABELS, Finding


def token_for(normalized: str, pii_type: str, tenant: str, hmac_secret: bytes) -> str:
    """Return a stable UUID-style token such as [PII_SSN_550e8400-e29b-41d4-a716-446655440000]."""
    material = f"{tenant}|{pii_type}|{normalized}".encode("utf-8")
    digest = hmac.new(hmac_secret, material, hashlib.sha256).digest()
    # RFC-4122-looking UUID from the first 16 bytes, variant bits set so it
    # is obviously an identifier and not the original value.
    uid = uuid.UUID(bytes=digest[:16], version=4)
    label = PII_LABELS.get(pii_type, pii_type.upper())
    return f"[PII_{label}_{uid}]"


def token_pattern() -> str:
    return r"\[PII_[A-Z]+(?:_[A-Z]+)*_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\]"


def assign_tokens(findings: list[Finding], tenant: str, hmac_secret: bytes) -> list[tuple[Finding, str]]:
    return [(finding, token_for(finding.normalized, finding.pii_type, tenant, hmac_secret)) for finding in findings]


def apply_tokens(text: str, assigned: list[tuple[Finding, str]]) -> str:
    """Replace findings with tokens, working from the end so offsets stay valid."""
    out = text
    for finding, token in sorted(assigned, key=lambda pair: pair[0].start, reverse=True):
        out = out[: finding.start] + token + out[finding.end :]
    return out
