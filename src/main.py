"""
main.py
-------
CLI entry point for the Azure ITGC Compliance Checker.

Usage:
    python src/main.py --config config.json
    python src/main.py --config config.json --no-save

What this file does:
  1. Reads your config.json (subscription ID)
  2. Authenticates to Azure using your `az login` session
  3. Runs each ITGC check in sequence
  4. Prints the formatted report to console
  5. Saves a JSON report file (unless --no-save is passed)
"""

import argparse
import json
import sys
from pathlib import Path

# Import our own modules
from azure_client import (
    get_credential,
    get_security_client,
    get_monitor_client,
    get_authorization_client,
    get_subscription_client,
)
from checks import (
    check_defender_for_cloud,
    check_activity_log_retention,
    check_privileged_access,
    check_security_contacts,
)
from report import print_report, save_json_report


def load_config(config_path: str) -> dict:
    """Load and validate the configuration file."""
    path = Path(config_path)
    if not path.exists():
        print(f"[ERROR] Config file not found: {config_path}")
        print("  Tip: Copy config.example.json to config.json and fill in your Subscription ID.")
        sys.exit(1)

    with open(path) as f:
        config = json.load(f)

    if not config.get("subscription_id") or config["subscription_id"] == "YOUR-AZURE-SUBSCRIPTION-ID-HERE":
        print("[ERROR] Please set a valid subscription_id in config.json")
        print("  Find it at: portal.azure.com > Subscriptions")
        sys.exit(1)

    return config


def get_subscription_display_name(credential, subscription_id: str) -> str:
    """Look up the human-readable subscription name from Azure."""
    try:
        sub_client = get_subscription_client(credential)
        sub = sub_client.subscriptions.get(subscription_id)
        return sub.display_name
    except Exception:
        return subscription_id  # Fallback to ID if lookup fails


def main():
    # -----------------------------------------------------------------------
    # 1. Parse CLI arguments
    # -----------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="Azure ITGC Compliance Checker - Automated NIST CSF 2.0 control testing"
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to config JSON file (default: config.json)"
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Skip saving JSON report file"
    )
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # 2. Load config
    # -----------------------------------------------------------------------
    config = load_config(args.config)
    subscription_id = config["subscription_id"]

    print("\n  Authenticating with Azure...")

    # -----------------------------------------------------------------------
    # 3. Authenticate and build SDK clients
    # -----------------------------------------------------------------------
    try:
        credential = get_credential()
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        print("  Tip: Run `az login` first to authenticate with Azure CLI.")
        sys.exit(1)

    # Resolve subscription display name
    subscription_name = config.get("subscription_name") or get_subscription_display_name(credential, subscription_id)

    print(f"  Connected to: {subscription_name}")
    print("  Running ITGC checks...\n")

    # Initialize SDK clients (one per Azure service area)
    security_client   = get_security_client(credential, subscription_id)
    monitor_client    = get_monitor_client(credential, subscription_id)
    auth_client       = get_authorization_client(credential, subscription_id)

    # -----------------------------------------------------------------------
    # 4. Run each ITGC control check
    # -----------------------------------------------------------------------
    results = [
        check_defender_for_cloud(security_client, subscription_id),
        check_activity_log_retention(monitor_client, subscription_id),
        check_privileged_access(auth_client, subscription_id),
        check_security_contacts(security_client, subscription_id),
    ]

    # -----------------------------------------------------------------------
    # 5. Output
    # -----------------------------------------------------------------------
    print_report(results, subscription_name, subscription_id)

    if not args.no_save:
        filename = save_json_report(results, subscription_name, subscription_id)
        print(f"  Full report saved to: {filename}")
        print()


if __name__ == "__main__":
    main()
