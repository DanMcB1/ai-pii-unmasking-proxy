"""Encrypted token → value vault (Fernet at rest).

The vault is the only place raw PII is stored after detection. The audit
log never gets the raw value. The key file is gitignored and labeled DEMO.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet

from pii_proxy.settings import vault_path


def _connect(path: Path | None = None) -> sqlite3.Connection:
    target = Path(path or vault_path())
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            tenant TEXT NOT NULL,
            pii_type TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    return conn


def put(
    token: str,
    value: str,
    pii_type: str,
    tenant: str,
    fernet_key: bytes,
    path: Path | None = None,
) -> None:
    cipher = Fernet(fernet_key).encrypt(value.encode("utf-8")).decode("ascii")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = _connect(path)
    try:
        conn.execute(
            """
            INSERT INTO tokens (token, tenant, pii_type, ciphertext, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(token) DO NOTHING
            """,
            (token, tenant, pii_type, cipher, now),
        )
        conn.commit()
    finally:
        conn.close()


def get(token: str, fernet_key: bytes, path: Path | None = None) -> dict | None:
    conn = _connect(path)
    try:
        row = conn.execute("SELECT * FROM tokens WHERE token = ?", (token,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    value = Fernet(fernet_key).decrypt(row["ciphertext"].encode("ascii")).decode("utf-8")
    return {
        "token": row["token"],
        "tenant": row["tenant"],
        "pii_type": row["pii_type"],
        "value": value,
        "created_at": row["created_at"],
    }


def lookup_many(tokens: list[str], fernet_key: bytes, path: Path | None = None) -> dict[str, dict]:
    return {tok: found for tok in tokens if (found := get(tok, fernet_key, path))}
