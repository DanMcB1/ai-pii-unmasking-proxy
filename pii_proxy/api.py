"""FastAPI proxy exposing an OpenAI-style /v1/chat/completions endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from pii_proxy.audit import read_log, verify_chain
from pii_proxy.pipeline import run_prompt
from pii_proxy.roles import known_roles, role_label
from pii_proxy.samples import SAMPLES, list_samples
from pii_proxy.settings import COMPANY, DEFAULT_TENANT

app = FastAPI(
    title="PII Unmasking Proxy",
    description=(
        f"Demo proxy for {COMPANY}. Masks PII before a model sees the prompt, "
        "then restores values only for authorized roles."
    ),
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "pii-proxy-mock"
    messages: list[ChatMessage]
    temperature: float | None = 0
    # Demo extensions: a real OpenAI client can ignore these and we still
    # honor role/actor via headers.
    actor: str | None = None
    user_role: str | None = Field(default=None, alias="role")
    tenant: str | None = None

    model_config = {"populate_by_name": True}


def _prompt_from_messages(messages: list[ChatMessage]) -> str:
    parts = []
    for msg in messages:
        if msg.role == "system":
            continue
        parts.append(msg.content)
    return "\n\n".join(parts).strip()


def _actor_and_role(
    body: ChatRequest | None = None,
    x_actor: str | None = None,
    x_role: str | None = None,
    x_tenant: str | None = None,
) -> tuple[str, str, str]:
    actor = (x_actor or (body.actor if body else None) or "demo.user").strip()
    role = (x_role or (body.user_role if body else None) or "sales_consultant").strip().lower()
    tenant = (x_tenant or (body.tenant if body else None) or DEFAULT_TENANT).strip()
    return actor, role, tenant


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "company": COMPANY}


@app.get("/v1/roles")
def roles() -> dict[str, Any]:
    return {
        "roles": [
            {"id": r, "label": role_label(r)} for r in known_roles()
        ]
    }


@app.get("/v1/samples")
def samples() -> dict[str, Any]:
    return {"samples": list_samples(), "detail": {k: {"title": v["title"], "prompt": v["prompt"], "actor": v["actor"], "role": v["role"]} for k, v in SAMPLES.items()}}


@app.get("/v1/audit")
def audit(limit: int = 50) -> dict[str, Any]:
    chain = verify_chain()
    return {"chain": chain, "entries": read_log(limit=limit)}


@app.get("/v1/audit/verify")
def audit_verify() -> dict[str, Any]:
    return verify_chain()


class ProxyRequest(BaseModel):
    prompt: str
    actor: str = "demo.user"
    role: str = "sales_consultant"
    tenant: str = DEFAULT_TENANT


@app.post("/v1/proxy")
def proxy(body: ProxyRequest) -> dict[str, Any]:
    result = run_prompt(body.prompt, actor=body.actor, role=body.role, tenant=body.tenant)
    return _result_payload(result)


@app.post("/v1/chat/completions")
def chat_completions(
    body: ChatRequest,
    x_actor: str | None = Header(default=None),
    x_role: str | None = Header(default=None),
    x_tenant: str | None = Header(default=None),
) -> dict[str, Any]:
    if not body.messages:
        raise HTTPException(status_code=400, detail="messages is required")
    actor, role, tenant = _actor_and_role(body, x_actor, x_role, x_tenant)
    prompt = _prompt_from_messages(body.messages)
    result = run_prompt(prompt, actor=actor, role=role, tenant=tenant)
    # OpenAI-shaped envelope plus demo fields the UI uses.
    return {
        "id": "chatcmpl-pii-proxy-demo",
        "object": "chat.completion",
        "model": body.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": result.delivered},
                "finish_reason": "stop",
            }
        ],
        "demo": _result_payload(result),
    }


def _result_payload(result) -> dict[str, Any]:
    return {
        "original": result.original,
        "masked": result.masked,
        "model_output": result.model_output,
        "restored": result.restored,
        "delivered": result.delivered,
        "unmasked": result.unmasked,
        "denied_reason": result.denied_reason,
        "findings": result.findings,
        "tokens": result.tokens,
        "actor": result.actor,
        "role": result.role,
        "tenant": result.tenant,
        "key_created": result.key_created,
    }
