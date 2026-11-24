"""Default mock LLM, plus an optional OpenAI-compatible hook (off by default)."""

from __future__ import annotations

import os
import re

from pii_proxy.settings import llm_api_key, llm_base_url, llm_model
from pii_proxy.tokens import token_pattern


TOKEN_RE = re.compile(token_pattern())


SYSTEM_NOTE = (
    "You are an F&I desk assistant at Lakeside Auto Group. The prompt has "
    "already had personal data replaced with tokens like [PII_SSN_…]. Quote "
    "those tokens exactly when you refer to a value. Do not invent new tokens."
)


def use_external() -> bool:
    return bool(llm_base_url())


def complete(masked_prompt: str) -> str:
    """Return a model response that refers to the tokens it was given."""
    if use_external():
        return _external(masked_prompt)
    return mock_complete(masked_prompt)


def mock_complete(masked_prompt: str) -> str:
    """Deterministic F&I-style review that quotes every token it sees."""
    tokens = TOKEN_RE.findall(masked_prompt)
    by_type: dict[str, list[str]] = {}
    for tok in tokens:
        # [PII_SSN_uuid] → SSN, [PII_CREDIT_CARD_uuid] → CREDIT_CARD
        inner = tok.strip("[]")
        rest = inner[4:] if inner.startswith("PII_") else inner
        label, _, _uid = rest.rpartition("_")
        by_type.setdefault(label or "PII", []).append(tok)

    lines = [
        "Lakeside Auto Group — F&I credit application review (demo)",
        "",
        "I reviewed the application as submitted. Personal values arrived as "
        "tokens, so I am quoting those tokens rather than any original numbers.",
        "",
    ]
    labels = {
        "NAME": "Applicant",
        "SSN": "Social Security number on file",
        "DOB": "Date of birth",
        "DL": "Driver's license",
        "PHONE": "Phone",
        "EMAIL": "Email",
        "CREDIT_CARD": "Card number provided for payment/deposit",
        "VIN": "Vehicle identification number",
        "ROUTING": "Bank routing number",
        "ACCOUNT": "Bank account number",
    }
    if tokens:
        lines.append("Application details I can see:")
        for label, heading in labels.items():
            for tok in by_type.get(label, []):
                lines.append(f"- {heading}: {tok}")
        # Any unexpected token types
        for label, toks in by_type.items():
            if label not in labels:
                for tok in toks:
                    lines.append(f"- {label}: {tok}")
        lines.append("")
        lines.append(
            "Recommended next step: confirm the tokenized identifiers with the "
            "desk manager before submitting the application to the lender. This "
            "is a demo response, not a credit decision."
        )
    else:
        lines.append(
            "No tokenized personal data appeared in the prompt. I can still "
            "help with process questions, but I have no application values to review."
        )
    return "\n".join(lines)


def _external(masked_prompt: str) -> str:
    """Best-effort call to an OpenAI-compatible /v1/chat/completions endpoint."""
    import urllib.error
    import urllib.request
    import json

    base = llm_base_url().rstrip("/")
    url = base + "/chat/completions" if base.endswith("/v1") else base + "/v1/chat/completions"
    payload = {
        "model": llm_model(),
        "messages": [
            {"role": "system", "content": SYSTEM_NOTE},
            {"role": "user", "content": masked_prompt},
        ],
        "temperature": 0,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    key = llm_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]
    except (urllib.error.URLError, KeyError, IndexError, TimeoutError) as exc:
        return (
            f"[External LLM call failed: {exc}. Falling back to the local mock.]\n\n"
            + mock_complete(masked_prompt)
        )
