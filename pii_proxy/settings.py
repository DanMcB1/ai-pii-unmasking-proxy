"""Paths and environment-driven settings. Key files are never committed."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPANY = "Lakeside Auto Group (sample)"
DEFAULT_TENANT = "lakeside-auto-group"

# Roles that may see restored (unmasked) values.
UNMASK_ROLES = frozenset(
    {
        "fi_manager",
        "controller",
        "compliance",
    }
)

ROLE_LABELS = {
    "fi_manager": "F&I Manager",
    "controller": "Controller",
    "compliance": "Compliance / Privacy",
    "sales_consultant": "Sales Consultant",
    "service_advisor": "Service Advisor",
}


def data_dir() -> Path:
    path = Path(os.environ.get("PII_PROXY_DATA", ROOT / "data"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def key_path() -> Path:
    return Path(os.environ.get("PII_PROXY_KEY_FILE", data_dir() / "demo.keys"))


def vault_path() -> Path:
    return Path(os.environ.get("PII_PROXY_VAULT", data_dir() / "vault.sqlite"))


def audit_path() -> Path:
    return Path(os.environ.get("PII_PROXY_AUDIT", data_dir() / "audit.jsonl"))


def llm_base_url() -> str:
    return os.environ.get("PII_PROXY_LLM_BASE_URL", "").strip()


def llm_api_key() -> str:
    return os.environ.get("PII_PROXY_LLM_API_KEY", "").strip()


def llm_model() -> str:
    return os.environ.get("PII_PROXY_LLM_MODEL", "mock-fi-reviewer")


def llm_is_external() -> bool:
    return bool(llm_base_url())


def proxy_url() -> str:
    return os.environ.get("PII_PROXY_URL", "http://127.0.0.1:8006")


def proxy_host() -> str:
    return os.environ.get("PII_PROXY_HOST", "127.0.0.1")


def proxy_port() -> int:
    return int(os.environ.get("PII_PROXY_PORT", "8006"))


def streamlit_port() -> int:
    return int(os.environ.get("PII_PROXY_UI_PORT", "8506"))
