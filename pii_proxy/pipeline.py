"""Mask → model → (optional) unmask, with vault + audit writes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pii_proxy import audit, detect, keys, llm, restore, roles, tokens, vault
from pii_proxy.settings import DEFAULT_TENANT


@dataclass
class PipelineResult:
    original: str
    masked: str
    model_output: str
    restored: str
    delivered: str
    unmasked: bool
    findings: list[dict] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    role: str = ""
    actor: str = ""
    tenant: str = ""
    denied_reason: str | None = None
    key_created: bool = False


def run_prompt(
    prompt: str,
    *,
    actor: str,
    role: str,
    tenant: str = DEFAULT_TENANT,
    key_file: Path | None = None,
    vault_file: Path | None = None,
    audit_file: Path | None = None,
    call_model: bool = True,
) -> PipelineResult:
    fernet_key, hmac_secret, created = keys.ensure_keys(key_file)
    findings = detect.detect(prompt)
    assigned = tokens.assign_tokens(findings, tenant, hmac_secret)
    masked = tokens.apply_tokens(prompt, assigned)

    for finding, token in assigned:
        vault.put(token, finding.value, finding.pii_type, tenant, fernet_key, vault_file)
        audit.append_event(
            event="mask",
            actor=actor,
            role=role,
            tenant=tenant,
            pii_type=finding.pii_type,
            token=token,
            path=audit_file,
        )

    model_output = llm.complete(masked) if call_model else ""
    allowed = roles.can_unmask(role)
    restored, restored_tokens, _unknown = restore.unmask_text(model_output, fernet_key, vault_file)

    if allowed:
        for tok in restored_tokens:
            found = vault.get(tok, fernet_key, vault_file)
            audit.append_event(
                event="unmask",
                actor=actor,
                role=role,
                tenant=tenant,
                pii_type=found["pii_type"] if found else "unknown",
                token=tok,
                path=audit_file,
            )
        delivered = restored
        denied = None
    else:
        for tok in restore.find_tokens(model_output):
            found = vault.get(tok, fernet_key, vault_file)
            audit.append_event(
                event="unmask_denied",
                actor=actor,
                role=role,
                tenant=tenant,
                pii_type=found["pii_type"] if found else "unknown",
                token=tok,
                path=audit_file,
            )
        delivered = model_output
        denied = f"Role {roles.role_label(role)} is not authorized to unmask."

    return PipelineResult(
        original=prompt,
        masked=masked,
        model_output=model_output,
        restored=restored,
        delivered=delivered,
        unmasked=allowed,
        findings=[
            {**finding.to_dict(), "token": token}
            for finding, token in assigned
        ],
        tokens=[token for _, token in assigned],
        role=role,
        actor=actor,
        tenant=tenant,
        denied_reason=denied,
        key_created=created,
    )
