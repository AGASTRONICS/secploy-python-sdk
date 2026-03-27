"""
Secploy SDK - Event ingestion, log capture, realtime config sync, and security gating for Python applications
"""

from .client import SecployClient
from .gates import GateDecision, GateRequest, SecurityGateException
from .handlers import SecployGate, SecurityGateBlocked, SecploySessionAdapter
from .schemas import SecployConfig
from .schemas import LogLevel
from .system_metrics import SystemMetricsCollector

__version__ = "1.0.0"
__author__ = "Abdulsamad .O. Abdulganiy"
__email__ = "support@secploy.com"
__description__ = "Event ingestion, log capture, realtime config sync, and security gating SDK for Python applications"

__all__ = [
    "SecployClient",
    "SecployGate",
    "SecurityGateBlocked",
    "SecploySessionAdapter",
    "SecurityGateException",
    "GateRequest",
    "GateDecision",
    "SecployConfig",
    "LogLevel",
    "SystemMetricsCollector",
]


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

_SECPLOY_TEMPLATE = """\
# .secploy — Secploy project configuration
# Docs: https://docs.secploy.com/sdk/configuration

api_key: YOUR_API_KEY
environment_key: YOUR_ENVIRONMENT_KEY
organization_id: YOUR_ORGANIZATION_ID

# environment: production
# api_url: https://api.secploy.com
# ingest_url: https://ingest.secploy.com
# debug: false
"""


def _load_creds(config_file=None):
    """Return (config_dict, error_string). error_string is None on success."""
    from .lib.config import load_config, find_project_config
    path = config_file or find_project_config()
    if not path:
        return None, (
            "No .secploy config file found.\n"
            "Run 'secploy init' to create one, or pass --config-file <path>."
        )
    cfg = load_config(path)
    missing = [k for k in ("api_key", "environment_key", "organization_id") if not cfg.get(k)]
    if missing:
        return None, f"Missing required fields in config: {', '.join(missing)}"
    return cfg, None


def _cmd_sync(args):
    """Handle `secploy sync --configs`."""
    import json
    import requests

    if not args.configs:
        print("Nothing to sync. Use --configs to fetch and write project configs.")
        return 1

    cfg, err = _load_creds(getattr(args, "config_file", None))
    if err:
        print(f"Error: {err}")
        return 1

    api_url = cfg.get("api_url", "https://api.secploy.com").rstrip("/")
    headers = {
        "X-API-Key": cfg["api_key"],
        "X-Environment-Key": cfg["environment_key"],
        "X-Organization-ID": cfg["organization_id"],
        "Content-Type": "application/json",
    }

    url = f"{api_url}/projects/configs/"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as exc:
        print(f"Error: Failed to reach Secploy API: {exc}")
        return 1

    if resp.status_code == 401:
        print("Error: Authentication failed. Check api_key, environment_key, and organization_id.")
        return 1
    if not resp.ok:
        print(f"Error: API returned {resp.status_code}: {resp.text[:300]}")
        return 1

    data = resp.json()
    configs: dict = data.get("configs", {})
    count = data.get("count", len(configs))
    environment = data.get("environment", "")

    output_file = args.output
    fmt = args.format

    if fmt == "json":
        content = json.dumps(configs, indent=2) + "\n"
    elif fmt == "yaml":
        import yaml
        content = yaml.dump(configs, default_flow_style=False)
    else:  # env (default)
        lines = []
        for k, v in configs.items():
            safe_v = str(v).replace('"', '\\"')
            lines.append(f'{k}="{safe_v}"')
        content = "\n".join(lines) + "\n"

    with open(output_file, "w") as fh:
        fh.write(content)

    print(f"Synced {count} config(s) [env: {environment}]  ->  {output_file}")
    return 0


def _cmd_init(args):
    """Handle `secploy init`."""
    import os
    target = os.path.join(os.getcwd(), ".secploy")
    if os.path.exists(target) and not args.force:
        print(f".secploy already exists at {target}. Use --force to overwrite.")
        return 1
    with open(target, "w") as fh:
        fh.write(_SECPLOY_TEMPLATE)
    print(f"Created {target}")
    print("Fill in api_key, environment_key, and organization_id, then run 'secploy sync --configs'.")
    return 0


def cli():
    """Command-line interface for the Secploy SDK."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="secploy",
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  secploy init                              Create a .secploy config template\n"
            "  secploy sync --configs                   Fetch configs -> .env\n"
            "  secploy sync --configs --output .env.local\n"
            "  secploy sync --configs --format json     Fetch configs -> configs.json\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"Secploy SDK v{__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── init ──────────────────────────────────────────────────────────────────
    init_parser = subparsers.add_parser(
        "init",
        help="Create a .secploy config template in the current directory",
    )
    init_parser.add_argument(
        "--force", action="store_true", help="Overwrite an existing .secploy file"
    )

    # ── sync ──────────────────────────────────────────────────────────────────
    sync_parser = subparsers.add_parser(
        "sync",
        help="Sync data from Secploy into local files",
    )
    sync_parser.add_argument(
        "--configs",
        action="store_true",
        help="Fetch project configs from the API and write them to a local file",
    )
    sync_parser.add_argument(
        "--output",
        metavar="FILE",
        default=".env",
        help="Output file path (default: .env)",
    )
    sync_parser.add_argument(
        "--format",
        choices=["env", "json", "yaml"],
        default="env",
        help="Output format: env | json | yaml  (default: env)",
    )
    sync_parser.add_argument(
        "--config-file",
        metavar="FILE",
        default=None,
        help="Path to .secploy config file (auto-detected from cwd upward if omitted)",
    )

    args = parser.parse_args()

    if args.command == "init":
        sys.exit(_cmd_init(args))
    elif args.command == "sync":
        sys.exit(_cmd_sync(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    import sys
    sys.exit(cli())
