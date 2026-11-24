"""Append-only, hash-chained audit log. Never stores raw PII."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pii_proxy.settings import audit_path

GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def entry_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    seq: int
    ts: str
    event: str
    actor: str
    role: str
    tenant: str
    pii_type: str
    token: str
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "event": self.event,
            "actor": self.actor,
            "role": self.role,
            "tenant": self.tenant,
            "pii_type": self.pii_type,
            "token": self.token,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


def _read_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def last_hash(path: Path | None = None) -> tuple[int, str]:
    rows = _read_lines(Path(path or audit_path()))
    if not rows:
        return 0, GENESIS
    return int(rows[-1]["seq"]), rows[-1]["entry_hash"]


def append_event(
    *,
    event: str,
    actor: str,
    role: str,
    tenant: str,
    pii_type: str,
    token: str,
    path: Path | None = None,
) -> AuditEntry:
    """Append one mask/unmask/unmask_denied event. Raises if the chain is already broken."""
    target = Path(path or audit_path())
    target.parent.mkdir(parents=True, exist_ok=True)
    # Verify before writing so we don't extend a tampered log silently.
    result = verify_chain(target)
    if not result["ok"]:
        raise RuntimeError(f"Audit log failed verification: {result['reason']}")
    seq, prev = last_hash(target)
    body = {
        "seq": seq + 1,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "actor": actor,
        "role": role,
        "tenant": tenant,
        "pii_type": pii_type,
        "token": token,
        "prev_hash": prev,
    }
    digest = entry_hash(body)
    body["entry_hash"] = digest
    # Reject accidental raw-value keys if a caller tries to sneak one in.
    for forbidden in ("value", "raw", "pii", "ssn", "number"):
        if forbidden in body:
            raise ValueError(f"Audit entries must not include field {forbidden!r}")
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(body, ensure_ascii=True) + "\n")
    return AuditEntry(**body)


def read_log(path: Path | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    rows = _read_lines(Path(path or audit_path()))
    if limit:
        return rows[-limit:]
    return rows


def verify_chain(path: Path | None = None) -> dict[str, Any]:
    """Walk the log and report the first break, if any."""
    target = Path(path or audit_path())
    rows = _read_lines(target)
    if not rows:
        return {"ok": True, "entries": 0, "reason": "empty log"}
    expected_prev = GENESIS
    expected_seq = 1
    for row in rows:
        if int(row.get("seq", -1)) != expected_seq:
            return {
                "ok": False,
                "entries": expected_seq - 1,
                "broken_at": row.get("seq"),
                "reason": f"Sequence gap: expected {expected_seq}, found {row.get('seq')}",
            }
        if row.get("prev_hash") != expected_prev:
            return {
                "ok": False,
                "entries": expected_seq - 1,
                "broken_at": row.get("seq"),
                "reason": f"prev_hash mismatch at seq {row.get('seq')}",
            }
        body = {k: v for k, v in row.items() if k != "entry_hash"}
        digest = entry_hash(body)
        if digest != row.get("entry_hash"):
            return {
                "ok": False,
                "entries": expected_seq - 1,
                "broken_at": row.get("seq"),
                "reason": f"entry_hash mismatch at seq {row.get('seq')} (content was altered)",
            }
        for forbidden in ("value", "raw", "ssn", "account_number"):
            if forbidden in row:
                return {
                    "ok": False,
                    "entries": expected_seq - 1,
                    "broken_at": row.get("seq"),
                    "reason": f"Forbidden field {forbidden!r} present in the audit log",
                }
        expected_prev = row["entry_hash"]
        expected_seq += 1
    return {"ok": True, "entries": len(rows), "reason": "chain intact", "tip": expected_prev}


def contains_raw_pii(text: str, raw_values: list[str]) -> list[str]:
    """Return any raw values that appear in text (used by tests and a safety check)."""
    hits = []
    for value in raw_values:
        if value and value in text:
            hits.append(value)
    return hits
