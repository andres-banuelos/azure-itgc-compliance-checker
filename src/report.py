"""
report.py
---------
Formats and outputs the compliance check results.

v1.0: Console output with color-coded status + JSON file export.

The console output is designed to be readable by both engineers
and audit managers - clean status table with risk context on failures.
"""

import json
import sys
from datetime import date

# ANSI color codes for terminal output
# Falls back gracefully if terminal doesn't support colors
GREEN  = "\033[92m" if sys.stdout.isatty() else ""
YELLOW = "\033[93m" if sys.stdout.isatty() else ""
RED    = "\033[91m" if sys.stdout.isatty() else ""
CYAN   = "\033[96m" if sys.stdout.isatty() else ""
BOLD   = "\033[1m"  if sys.stdout.isatty() else ""
RESET  = "\033[0m"  if sys.stdout.isatty() else ""


def _status_color(status: str) -> str:
    """Returns color-coded status string for terminal display."""
    colors = {
        "PASS": f"{GREEN}[ PASS ]{RESET}",
        "FAIL": f"{RED}[ FAIL ]{RESET}",
        "WARN": f"{YELLOW}[ WARN ]{RESET}",
        "ERROR": f"{YELLOW}[ERROR ]{RESET}",
    }
    return colors.get(status, f"[{status:^6}]")


def print_report(results: list, subscription_name: str, subscription_id: str):
    """
    Prints the formatted compliance report to the console.

    Args:
        results: List of finding dicts from checks.py
        subscription_name: Display name of the Azure subscription
        subscription_id: Azure Subscription ID
    """
    today = date.today().strftime("%Y-%m-%d")
    pass_count = sum(1 for r in results if r["status"] == "PASS")
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    warn_count = sum(1 for r in results if r["status"] in ("WARN", "ERROR"))

    # Determine overall risk rating
    if fail_count >= 2:
        risk_rating = f"{RED}HIGH{RESET}"
    elif fail_count == 1 or warn_count >= 2:
        risk_rating = f"{YELLOW}MEDIUM{RESET}"
    elif warn_count == 1:
        risk_rating = f"{YELLOW}LOW-MEDIUM{RESET}"
    else:
        risk_rating = f"{GREEN}LOW{RESET}"

    # Header
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  AZURE ITGC COMPLIANCE CHECKER  |  v1.0{RESET}")
    print(f"  Subscription : {CYAN}{subscription_name}{RESET}")
    print(f"  Sub ID       : {subscription_id[:8]}...")
    print(f"  Run Date     : {today}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    # Results table
    for r in results:
        status_str = _status_color(r["status"])
        print(f"  {r['control_id']:<10} {r['control_name']:<38} {status_str}")
        print(f"  {'':10} {CYAN}{r['nist_ref']}{RESET}  {r['detail']}")
        if r.get("risk") and r["status"] in ("FAIL", "WARN", "ERROR"):
            print(f"  {'':10} {YELLOW}Risk:{RESET} {r['risk']}")
        print()

    # Summary footer
    print(f"{BOLD}{'-'*60}{RESET}")
    print(f"  Results: {GREEN}{pass_count} PASS{RESET}  |  {RED}{fail_count} FAIL{RESET}  |  {YELLOW}{warn_count} WARN{RESET}")
    print(f"  Overall Risk Rating: {risk_rating}")
    print(f"{BOLD}{'-'*60}{RESET}\n")


def save_json_report(results: list, subscription_name: str, subscription_id: str) -> str:
    """
    Saves findings to a structured JSON file for further processing,
    ticketing system integration, or audit workpaper attachment.

    Returns the filename of the saved report.
    """
    today = date.today().strftime("%Y%m%d")
    filename = f"itgc_report_{today}.json"

    report_data = {
        "tool": "Azure ITGC Compliance Checker v1.0",
        "run_date": date.today().isoformat(),
        "subscription_name": subscription_name,
        "subscription_id": subscription_id,
        "framework": "NIST CSF 2.0",
        "summary": {
            "pass": sum(1 for r in results if r["status"] == "PASS"),
            "fail": sum(1 for r in results if r["status"] == "FAIL"),
            "warn": sum(1 for r in results if r["status"] in ("WARN", "ERROR")),
        },
        "findings": results
    }

    with open(filename, "w") as f:
        json.dump(report_data, f, indent=2)

    return filename
