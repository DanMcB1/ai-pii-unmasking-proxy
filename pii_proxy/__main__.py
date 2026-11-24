"""CLI: python -m pii_proxy verify-chain | serve | once."""

from __future__ import annotations

import argparse
import json
import sys

from pii_proxy.audit import verify_chain
from pii_proxy.pipeline import run_prompt
from pii_proxy.samples import SAMPLES
from pii_proxy.settings import proxy_host, proxy_port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pii_proxy", description="Deterministic PII Unmasking Proxy (demo)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("verify-chain", help="Verify the append-only audit log hash chain")

    serve = sub.add_parser("serve", help="Start the FastAPI proxy")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    once = sub.add_parser("once", help="Mask, call the model, and print a one-shot result")
    once.add_argument("--sample", default="credit_application", choices=list(SAMPLES))
    once.add_argument("--role", default=None)
    once.add_argument("--actor", default=None)
    once.add_argument("--prompt", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "verify-chain":
        result = verify_chain()
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 2

    if args.cmd == "serve":
        import uvicorn

        uvicorn.run(
            "pii_proxy.api:app",
            host=args.host or proxy_host(),
            port=args.port or proxy_port(),
            reload=False,
        )
        return 0

    if args.cmd == "once":
        sample = SAMPLES[args.sample]
        prompt = args.prompt or sample["prompt"]
        result = run_prompt(
            prompt,
            actor=args.actor or sample["actor"],
            role=args.role or sample["role"],
        )
        print(json.dumps({
            "masked": result.masked,
            "model_output": result.model_output,
            "delivered": result.delivered,
            "unmasked": result.unmasked,
            "findings": result.findings,
            "denied_reason": result.denied_reason,
        }, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
