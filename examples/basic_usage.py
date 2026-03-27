"""Basic Secploy SDK usage example.

Usage:
    python examples/basic_usage.py
    python examples/basic_usage.py --config-file .secploy

Expected setup:
- A .secploy file in project root (or pass --config-file).
- Required keys: api_key, environment_key, organization_id.
"""

from __future__ import annotations

import argparse
import time

from secploy import SecployClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run basic Secploy SDK example")
    parser.add_argument(
        "--config-file",
        default=None,
        help="Path to config file (default: auto-detect .secploy)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        client = SecployClient(config_file=args.config_file)
    except Exception as exc:
        print(f"Failed to initialize SecployClient: {exc}")
        return 1

    print("Secploy client initialized.")

    try:
        # Send one custom business event
        ok = client.send_event(
            "example.user_signup",
            {
                "user_id": "u_demo_001",
                "plan": "pro",
                "source": "basic_usage_example",
            },
        )
        print(f"send_event returned: {ok}")

        # Access remote project configs
        try:
            feature_flag = client.configs.get("FEATURE_NEW_DASHBOARD", default="false")
            print(f"FEATURE_NEW_DASHBOARD={feature_flag}")
        except Exception as exc:
            print(f"Config fetch warning: {exc}")

        # Optional: capture logs from this module logger
        client.capture_logs(__name__)

        # Keep process alive briefly so background processor can flush
        time.sleep(2)

    finally:
        client.stop()
        print("Secploy client stopped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
