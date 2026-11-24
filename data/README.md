This folder holds runtime data created on first run:

- `demo.keys` — Fernet + HMAC demo keys (gitignored)
- `vault.sqlite` — encrypted token-to-value vault (gitignored)
- `audit.jsonl` — append-only hash-chained audit log (gitignored)

None of those files should be committed. They are generated locally by `./run.sh` or `python -m pii_proxy once`.
