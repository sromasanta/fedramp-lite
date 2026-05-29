"""
reporter.py
-----------
Builds the final compliance report, prints it to the terminal,
and saves it as a JSON file to the reports/ directory.
"""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from colorama import init, Fore, Style

init(autoreset=True)

# ── Color + icon maps ─────────────────────────────────────────────────────────

_COLOR = {
    "compliant":           Fore.GREEN,
    "partially-compliant": Fore.YELLOW,
    "non-compliant":       Fore.RED,
}

_ICON = {
    "compliant":           "[PASS]",
    "partially-compliant": "[WARN]",
    "non-compliant":       "[FAIL]",
}


# ── Public API ────────────────────────────────────────────────────────────────

def build_report(results: list[dict]) -> dict:
    """
    Wrap control results in a report envelope with metadata and summary counts.
    Overall status is worst-case across all controls:
      non-compliant > partially-compliant > compliant
    """
    counts = {"compliant": 0, "partially-compliant": 0, "non-compliant": 0}
    for r in results:
        status = r.get("status", "non-compliant")
        counts[status] = counts.get(status, 0) + 1

    if counts["non-compliant"] > 0:
        overall = "non-compliant"
    elif counts["partially-compliant"] > 0:
        overall = "partially-compliant"
    else:
        overall = "compliant"

    return {
        "report_title":   "FedRAMP-Lite Compliance Report",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "summary":        counts,
        "controls":       results,
    }


def save_report(report: dict, output_dir: str) -> str:
    """Write the report as indented JSON. Returns the saved file path."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filepath  = os.path.join(output_dir, f"report_{timestamp}.json")

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return filepath


def print_report(report: dict) -> None:
    """Print a color-coded compliance summary to stdout."""
    _print_header(report)
    for control in report["controls"]:
        _print_control(control)
    _print_summary(report)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _print_header(report: dict) -> None:
    overall = report["overall_status"]
    width   = 62
    print()
    print(Style.BRIGHT + "=" * width)
    print(Style.BRIGHT + f"  {report['report_title']}")
    print(f"  Generated : {report['generated_at']}")
    print(f"  Overall   : {_COLOR[overall]}{Style.BRIGHT}{overall.upper()}")
    print(Style.BRIGHT + "=" * width)


def _print_control(control: dict) -> None:
    status = control.get("status", "non-compliant")
    color  = _COLOR.get(status, "")
    icon   = _ICON.get(status, "[?]")
    error  = control.get("error")

    print()
    # Control header line
    print(
        Style.BRIGHT +
        f"  {color}{icon}{Style.RESET_ALL}{Style.BRIGHT}"
        f"  {control['control_id']} - {control['control_name']}"
        f"  [{control.get('family','')}]"
    )
    print(f"       Status   : {color}{status.upper()}")
    print(f"       Evidence : {control.get('evidence_used','?')}")

    if error:
        print(f"       {Fore.RED}ERROR: {error}")
        return

    # Individual findings
    for finding in control.get("findings", []):
        if finding["passed"]:
            marker = Fore.GREEN + "    + "
        else:
            marker = Fore.RED   + "    - "
        print(f"{marker}{Style.RESET_ALL}{finding['detail']}")


def _print_summary(report: dict) -> None:
    s = report["summary"]
    print()
    print(Style.BRIGHT + "-" * 62)
    print(Style.BRIGHT + "  SUMMARY")
    print(f"  {Fore.GREEN}Compliant            : {s.get('compliant', 0)}")
    print(f"  {Fore.YELLOW}Partially Compliant  : {s.get('partially-compliant', 0)}")
    print(f"  {Fore.RED}Non-Compliant        : {s.get('non-compliant', 0)}")
    print(f"  {'Total Controls':21}: {sum(s.values())}")
    print(Style.BRIGHT + "-" * 62)
    print()