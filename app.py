"""Deterministic PII Unmasking Proxy — Streamlit UI.

Run with ./run.sh  (starts the FastAPI proxy and this app)
"""

from __future__ import annotations

import json

import httpx
import pandas as pd
import streamlit as st

from pii_proxy.audit import read_log, verify_chain
from pii_proxy.pipeline import run_prompt
from pii_proxy.roles import known_roles, role_label, can_unmask
from pii_proxy.samples import SAMPLES
from pii_proxy.settings import COMPANY, DEFAULT_TENANT, proxy_url

st.set_page_config(
    page_title="PII Unmasking Proxy",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
  .block-container { padding-top: 1.2rem; max-width: 1360px; }
  .demo-banner {
    background: #fff6e5;
    border: 1px solid #e6d2a8;
    color: #5a4500;
    padding: 0.7rem 1rem;
    border-radius: 8px;
    font-size: 0.95rem;
    margin-bottom: 0.8rem;
  }
  .panel {
    background: #fff;
    border: 1px solid #d5dbe3;
    border-radius: 10px;
    padding: 0.75rem 0.9rem 0.6rem;
    margin-bottom: 0.7rem;
  }
  .panel-label {
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #4a5a70;
    font-weight: 700;
    margin: 0 0 0.4rem;
  }
  .panel pre {
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 0.82rem;
    line-height: 1.45;
    margin: 0;
    color: #1c2430;
  }
  .ok { color: #2a7f6f; font-weight: 700; }
  .warn { color: #8a5a00; font-weight: 700; }
  .bad { color: #9b2c2c; font-weight: 700; }
  h1 { letter-spacing: -0.02em; }
  div[data-testid="stMetric"] {
    background: #f3f5f8;
    border: 1px solid #d5dbe3;
    border-radius: 10px;
    padding: 8px 12px;
  }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def _api_up() -> bool:
    try:
        resp = httpx.get(proxy_url() + "/health", timeout=0.6)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def _run(prompt: str, actor: str, role: str, tenant: str) -> dict:
    if _api_up():
        resp = httpx.post(
            proxy_url() + "/v1/proxy",
            json={"prompt": prompt, "actor": actor, "role": role, "tenant": tenant},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    result = run_prompt(prompt, actor=actor, role=role, tenant=tenant)
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
        "via": "in-process",
    }


def _panel(label: str, text: str) -> None:
    escaped = (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    st.markdown(
        f'<div class="panel"><div class="panel-label">{label}</div>'
        f"<pre>{escaped}</pre></div>",
        unsafe_allow_html=True,
    )


api_up = _api_up()

with st.sidebar:
    st.header("How this works")
    st.markdown(
        """
A credit application often has an SSN, a date of birth, a card number, a VIN, and bank details. Those should not go to a model vendor.

This **proxy** sits in the middle. It finds personal data, replaces each value with a **stable token**, sends the tokenized prompt to a local mock model, then **puts the original values back** only if you have the right role.
        """
    )
    st.markdown("---")
    st.markdown("**Who is asking**")
    role_ids = known_roles()
    role = st.selectbox(
        "Role",
        role_ids,
        index=role_ids.index("fi_manager"),
        format_func=role_label,
        help="F&I Manager, Controller, and Compliance can unmask. Sales and Service see tokens only.",
    )
    actor = st.text_input("Actor", value="jordan.lee")
    tenant = st.text_input("Tenant", value=DEFAULT_TENANT)
    if can_unmask(role):
        st.caption("This role **can** see restored values.")
    else:
        st.caption("This role **cannot** unmask. The delivered response will still have tokens.")
    st.markdown("---")
    st.subheader("Sample prompts")
    st.caption("Fictional Lakeside Auto Group data. Nothing is sent to a paid model.")
    for key, meta in SAMPLES.items():
        if st.button(meta["title"], key=f"sample_{key}", use_container_width=True):
            st.session_state["prompt"] = meta["prompt"]
            st.session_state["autorun"] = True
    st.markdown("---")
    st.markdown("**Proxy status**")
    st.write("API:", "reachable at " + proxy_url() if api_up else "not reachable — start with `./run.sh` (in-process fallback is on)")
    st.caption("Default model is a local mock. Optional OpenAI-compatible / Ollama hook is off unless `PII_PROXY_LLM_BASE_URL` is set.")
    st.markdown("---")
    st.caption(f"Portfolio demo for Daniel McBrearty · {COMPANY}")

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("Deterministic PII Unmasking Proxy")
st.caption(
    "Mask personal data before a model sees it, restore it only for the people who should see it, "
    "and keep a tamper-evident log of every mask and unmask."
)
st.markdown(
    '<div class="demo-banner">'
    "<strong>Honest label:</strong> this is a demo for "
    f"{COMPANY}. All application values are fictional. Detection is regex plus checksums "
    "(Luhn, ABA routing, VIN), not a certified DLP product. The vault key is a local "
    "<em>demo</em> file, not a KMS. The default model runs on this machine and never "
    "calls a paid API. This is not a compliance certification."
    "</div>",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Prompt + run
# ---------------------------------------------------------------------------
if "prompt" not in st.session_state:
    st.session_state["prompt"] = SAMPLES["credit_application"]["prompt"]
prompt = st.text_area(
    "Prompt to the model",
    height=260,
    key="prompt",
)

run_clicked = st.button("Run through the proxy", type="primary")
if run_clicked or st.session_state.pop("autorun", False):
    try:
        st.session_state["result"] = _run(prompt, actor=actor, role=role, tenant=tenant)
        st.session_state["result_error"] = None
    except Exception as exc:  # noqa: BLE001
        st.session_state["result_error"] = str(exc)

if st.session_state.get("result_error"):
    st.error(st.session_state["result_error"])

result = st.session_state.get("result")

if result:
    n_findings = len(result.get("findings") or [])
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("PII values found", n_findings)
    m2.metric("Delivered", "Unmasked" if result.get("unmasked") else "Tokens only")
    m3.metric("Role", role_label(result.get("role", "")))
    chain = verify_chain()
    m4.metric("Audit chain", "Intact" if chain.get("ok") else "BROKEN")
    if result.get("denied_reason"):
        st.warning(result["denied_reason"])
    if result.get("key_created"):
        st.info("A new demo key file was created at data/demo.keys. It is gitignored and is not production key management.")

    left, right = st.columns(2)
    with left:
        _panel("1. Original prompt (what the caller wrote)", result.get("original") or "")
        _panel("3. Raw model output (still tokenized)", result.get("model_output") or "")
    with right:
        _panel("2. What the model saw (PII replaced with tokens)", result.get("masked") or "")
        delivered_label = (
            "4. Restored output (authorized caller)"
            if result.get("unmasked")
            else "4. Delivered output (role not authorized to unmask)"
        )
        _panel(delivered_label, result.get("delivered") or "")

    if result.get("findings"):
        st.markdown("#### Findings")
        rows = []
        for item in result["findings"]:
            rows.append(
                {
                    "Type": item.get("pii_type"),
                    "Token": item.get("token"),
                    "Original value (authorized view in this demo UI)": item.get("value")
                    if result.get("unmasked")
                    else "— hidden —",
                }
            )
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        if result.get("unmasked"):
            st.caption(
                "The findings table shows original values only because the selected role is allowed to unmask. "
                "The audit log and the model input still never store those raw values."
            )

tab_audit, tab_verify = st.tabs(["Audit trail", "Verify hash chain"])

with tab_audit:
    st.markdown("#### Append-only audit log")
    st.caption(
        "Each row records a token, a PII type, who, when, and a hash that includes the previous row. "
        "Raw values are never written here."
    )
    entries = read_log(limit=80)
    if not entries:
        st.info("No audit entries yet. Run a prompt through the proxy.")
    else:
        view = pd.DataFrame(entries)
        keep = [c for c in ["seq", "ts", "event", "actor", "role", "tenant", "pii_type", "token", "prev_hash", "entry_hash"] if c in view.columns]
        st.dataframe(view[keep], use_container_width=True, hide_index=True)

with tab_verify:
    st.markdown("#### Tamper-evident chain")
    st.caption("Same check as `python -m pii_proxy verify-chain`. If someone edits a past line, the hashes stop lining up.")
    if st.button("Verify chain now"):
        st.session_state["chain"] = verify_chain()
    chain = st.session_state.get("chain") or verify_chain()
    if chain.get("ok"):
        st.success(f"Chain intact · {chain.get('entries', 0)} entries · {chain.get('reason')}")
    else:
        st.error(f"Chain broken · {chain.get('reason')}")
    st.code(json.dumps(chain, indent=2), language="json")
