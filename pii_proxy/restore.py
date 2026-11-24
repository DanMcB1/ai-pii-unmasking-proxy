"""Restore tokens in model output for authorized callers only."""

from __future__ import annotations

import re

from pii_proxy.tokens import token_pattern
from pii_proxy.vault import lookup_many


TOKEN_RE = re.compile(token_pattern())


def find_tokens(text: str) -> list[str]:
    # Preserve order, unique.
    seen: list[str] = []
    for match in TOKEN_RE.finditer(text):
        tok = match.group(0)
        if tok not in seen:
            seen.append(tok)
    return seen


def unmask_text(text: str, fernet_key: bytes, vault_path=None) -> tuple[str, list[str], list[str]]:
    """Replace known tokens with vault values.

    Returns (text, restored_tokens, unknown_tokens). Unknown tokens are left as-is.
    """
    tokens = find_tokens(text)
    found = lookup_many(tokens, fernet_key, vault_path)
    unknown = [tok for tok in tokens if tok not in found]
    out = text
    for tok in tokens:
        if tok in found:
            out = out.replace(tok, found[tok]["value"])
    return out, [tok for tok in tokens if tok in found], unknown
