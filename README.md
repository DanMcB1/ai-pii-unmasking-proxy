# Deterministic PII Unmasking Proxy

A small, local demo of a **privacy proxy** that sits between an application and a language model. Before the model sees a prompt, the proxy finds personal data (SSNs, card numbers, phone numbers, emails, dates of birth, driver’s licenses, VINs, bank routing and account numbers, and labeled names), replaces each value with a **stable token**, and only later puts the original values back — and only if the caller is allowed to see them.

This is a **portfolio demo**, not production software and not a compliance certification. Detection is regex plus checksums, not a certified DLP product. The vault key is a local demo file, not a KMS. The default model is a mock that runs on this machine and never calls a paid API.

Built for **Daniel McBrearty** as part of a Forward Deployed Engineer / solutions engineer portfolio. The sample company is **Lakeside Auto Group**, the same fictional mid-size dealer group used in the other portfolio demos.

## Why this matters for FDE work

Regulated customers will not send a credit application to a model vendor. An F&I desk already treats a deal jacket that way: the Social Security number, the card used for a deposit, the VIN, and the bank account for an ACH are not something you paste into a third-party tool.

An FDE is often the person who has to make an AI feature usable *without* asking the customer to relax that rule. The usual pattern is: detect and tokenize on the way in, let the model work with tokens, restore values only for the people who are allowed to see them, and keep a log of every mask and unmask that a compliance team can trust.

That is what this proxy shows, in one screen, on a Lakeside Honda credit application.

## Quick start

```bash
git clone https://github.com/DanMcB1/ai-pii-unmasking-proxy.git
cd ai-pii-unmasking-proxy
./run.sh
```

Then open [http://127.0.0.1:8506](http://127.0.0.1:8506). The script creates a local virtualenv, starts the FastAPI proxy on port **8006**, and starts the Streamlit UI on port **8506**.

Useful one-liners, once the venv exists:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pii_proxy once --sample credit_application --role fi_manager
.venv/bin/python -m pii_proxy once --sample credit_application --role sales_consultant
.venv/bin/python -m pii_proxy verify-chain
```

The OpenAI-style endpoint is `POST /v1/chat/completions`. Pass the role as the `X-Role` header (`fi_manager`, `controller`, `compliance`, `sales_consultant`, or `service_advisor`). A successful response looks like a normal chat completion, with a `demo` object that includes the original prompt, the masked prompt, the raw model output, and the delivered text.

An optional OpenAI-compatible or Ollama backend is supported with `PII_PROXY_LLM_BASE_URL` (and optional `PII_PROXY_LLM_API_KEY`, `PII_PROXY_LLM_MODEL`). It is **off by default**. If the variable is unset, the proxy uses a deterministic local mock that quotes the tokens it was given.

## What’s on the screen

- An honest banner that this is a demo, not certified DLP
- A role picker: F&I Manager, Controller, and Compliance can unmask; Sales Consultant and Service Advisor cannot
- One-click sample prompts, including a full Lakeside Honda credit application
- Four panels side by side: **original prompt**, **what the model saw**, **raw model output**, and **restored (or still-tokenized) output**
- A findings table, an append-only audit trail, and a **Verify hash chain** button (the same check as `python -m pii_proxy verify-chain`)

## How it works

1. **Detect.** Regex rules plus checksums: Luhn for cards, the ABA weights for routing numbers, and the ISO 3779 check digit for VINs. A 13–19 digit run (with or without spaces or dashes) is never tagged as a phone or bank account, even if Luhn fails; if it sits next to a card label it is still treated as a card, so a mistyped check digit is masked instead of leaked or mislabeled. VINs must also contain at least one letter — a 17-digit numeric run is not a VIN even if the ISO 3779 check digit happens to pass, and it follows the 13–19 digit rule instead. Bare 9-digit numbers are not treated as SSNs unless a label is next to them. Names are a simple labeled heuristic (`Applicant name:`, `Customer:`, `Borrower:`), not a full NER model.
2. **Tokenize deterministically.** Each value is normalized (digits only for an SSN, and so on) and run through HMAC-SHA256 with the tenant and the PII type. The first 16 bytes become a UUID-style token such as `[PII_SSN_550e8400-e29b-41d4-a716-446655440000]`. The same SSN always maps to the same token inside one tenant, and a different tenant gets a different token for the same value.
3. **Vault.** The token-to-value map is stored in a local SQLite file, with each value encrypted using Fernet and a key in `data/demo.keys`. That file is gitignored and labeled as a demo key. It is created on first run.
4. **Model.** The masked prompt is sent to the local mock (or, if configured, to an OpenAI-compatible endpoint). The mock writes a short F&I review that quotes the tokens — it never sees the raw values.
5. **Restore, sometimes.** If the caller’s role is allowed to unmask, tokens in the model output are replaced with vault values. Otherwise the caller gets the tokenized output, and the denial is logged.
6. **Audit.** Every mask, unmask, and unmask-denied event is appended to `data/audit.jsonl` as a hash-chained entry: sequence, timestamp, event, actor, role, tenant, PII type, token, previous hash, and this entry’s hash. The raw value is never written to the log. `verify-chain` walks the file and reports the first break if someone edits a past line.

## Honest limitations

- This is a **demo**. Lakeside Auto Group is fictional. The credit application values are obviously fake (an `example.com` email, a 555 number, the well-known test Visa).
- Detection will **miss** some values and can **false-positive**. Regex does not understand context the way a person or a maintained DLP engine does. A Social Security number written as words, a card number broken across lines, or a nickname with no label will slip through.
- This is **not** a certified compliance control, not GLBA advice, and not a substitute for a vendor review, a BAA, or a DLP product such as Presidio or a commercial service.
- Identity is a dropdown. There is no SSO, and nothing stops someone from picking “F&I Manager.”
- The vault key is a **file on disk**. Anyone with that file and the SQLite database can decrypt values. That is acceptable for a local demo and not acceptable in production.
- The default “model” is a template. It is deterministic on purpose, so the demo runs offline and the tests can assert that tokens come back.
- The audit log is hash-chained, which detects silent edits. It is not a WORM store, not signed by an HSM, and not replicated.

## What a production version would add

- A real DLP / NER stack (Microsoft Presidio, a cloud DLP API, or a customer-approved engine) next to these deterministic rules, with a way to review misses
- Keys in a KMS or HSM, with rotation, per-tenant wrapping keys, and no raw key file on the app host
- SSO and a real authorization check for who may unmask, including break-glass and two-person rules for full SSN or PAN reveal
- Token format and vault retention agreed with the customer’s compliance team, plus automatic expiry
- A production audit stream: append-only storage, external integrity (for example a signed checkpoint), and an export path for e-discovery
- Network isolation so the only process that can reach the vault is the proxy, and the model vendor never sees it
- Redaction policies that go beyond PII (deal numbers, lender names, free-text notes) and a human review queue for low-confidence detections
- Load, latency, and failure-mode testing in front of the real model endpoint

## Project layout

```
ai-pii-unmasking-proxy/
  app.py                 Streamlit UI (side-by-side original / masked / output)
  run.sh                 Starts the FastAPI proxy and the UI
  requirements.txt
  README.md
  LICENSE                MIT, Copyright (c) 2026 Daniel McBrearty
  DEMO_SCRIPT.md
  pii_proxy/             Detect, tokenize, vault, audit, mock LLM, API
  tests/
  examples/
  screenshots/
  data/                  Demo keys, vault, and audit log (gitignored)
```

## For interviewers

Start `./run.sh`, leave the role on **F&I Manager**, click **Run through the proxy**, and point at the four panels. The SSN, card, VIN, and bank numbers are in the original and in the restored output, and they are tokens in the two middle panels. Then switch the role to **Sales Consultant**, run it again, and show that the delivered text stays tokenized. If there is time, click **Verify hash chain** or run `python -m pii_proxy verify-chain`. The talk track is in [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md).

Daniel’s background is car sales, F&I, and auto software sales (Dealr.cloud), not professional security engineering. This project is meant to show he understands **why a deal jacket should not be pasted into a model vendor, how deterministic tokens keep a conversation usable, and why the audit log must not itself become a pile of Social Security numbers**.

## License

This project is released under the [MIT License](LICENSE). Copyright (c) 2026 Daniel McBrearty.
