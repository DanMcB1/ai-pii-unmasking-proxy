"""Who is allowed to see unmasked values."""

from __future__ import annotations

from pii_proxy.settings import ROLE_LABELS, UNMASK_ROLES


def can_unmask(role: str) -> bool:
    return (role or "").strip().lower() in UNMASK_ROLES


def role_label(role: str) -> str:
    key = (role or "").strip().lower()
    return ROLE_LABELS.get(key, role or "unknown")


def known_roles() -> list[str]:
    return list(ROLE_LABELS.keys())
