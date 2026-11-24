"""Demo key handling. Keys live in a local file that is gitignored.

This is deliberately simple and clearly *not* production key management.
The file is created on first run with a warning in the logs and the UI.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

from pii_proxy.settings import key_path

HEADER = (
    "# DEMO KEY FILE — not for production.\n"
    "# Generated locally for the PII Unmasking Proxy portfolio demo.\n"
    "# Do not commit this file. Do not reuse these keys outside this demo.\n"
    "# Production would keep these in a KMS or HSM, not a file on disk.\n"
)


def ensure_keys(path: Path | None = None) -> tuple[bytes, bytes, bool]:
    """Return (fernet_key, hmac_secret, created_new)."""
    target = Path(path or key_path())
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        fernet, hmac_secret = _read(target)
        return fernet, hmac_secret, False
    fernet = Fernet.generate_key()
    hmac_secret = Fernet.generate_key()  # 32+ url-safe bytes, fine as HMAC key
    target.write_text(
        HEADER + f"FERNET={fernet.decode()}\nHMAC={hmac_secret.decode()}\n",
        encoding="utf-8",
    )
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return fernet, hmac_secret, True


def _read(path: Path) -> tuple[bytes, bytes]:
    fernet = hmac_secret = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("FERNET="):
            fernet = line.split("=", 1)[1].strip().encode()
        elif line.startswith("HMAC="):
            hmac_secret = line.split("=", 1)[1].strip().encode()
    if not fernet or not hmac_secret:
        raise RuntimeError(f"Key file {path} is missing FERNET or HMAC lines.")
    return fernet, hmac_secret
