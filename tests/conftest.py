"""Isolate key/vault/audit files per test."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def isolated_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("PII_PROXY_DATA", str(tmp_path))
    monkeypatch.setenv("PII_PROXY_KEY_FILE", str(tmp_path / "demo.keys"))
    monkeypatch.setenv("PII_PROXY_VAULT", str(tmp_path / "vault.sqlite"))
    monkeypatch.setenv("PII_PROXY_AUDIT", str(tmp_path / "audit.jsonl"))
    # Make sure no leftover env points at the shared demo data dir.
    monkeypatch.delenv("PII_PROXY_LLM_BASE_URL", raising=False)
    return tmp_path
