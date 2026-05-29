"""
main.py
-------
Entry point for the FedRAMP-Lite Compliance Automation Engine.

Usage
-----
  python main.py
  python main.py --evidence evidence/ --catalog controls/catalog.yaml

Pipeline
--------
  1. Load control catalog  (controls/catalog.yaml)
  2. Load all evidence files from evidence/
  3. Evaluate each control against its evidence
  4. Build + save a JSON report to reports/
  5. Print a color-coded summary to the terminal
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from engine.loader    import load_catalog, load_all_evidence
from engine.evaluator import evaluate_control
from engine.reporter  import build_report, save_report, print_report


BASE_DIR         = os.path.dirname(__file__)
DEFAULT_CATALOG  = os.path.join(BASE_DIR, "controls", "catalog.yaml")
DEFAULT_EVIDENCE = os.path.join(BASE_DIR, "evidence")
DEFAULT_OUTPUT   = os.path.join(BASE_DIR, "reports")


def parse_args():
    parser = argparse.ArgumentParser(
        description="FedRAMP-Lite: simple compliance automation engine."
    )
    parser.add_argument("--catalog",  default=DEFAULT_CATALOG,
                        help="Path to YAML control catalog")
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE,
                        help="Directory containing evidence files")
    parser.add_argument("--output",   default=DEFAULT_OUTPUT,
                        help="Directory to write the JSON report")
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"\n[*] Loading catalog  : {args.catalog}")
    catalog = load_catalog(args.catalog)
    print(f"    {len(catalog)} controls found.")

    print(f"[*] Loading evidence : {args.evidence}")
    evidence_map = load_all_evidence(args.evidence)
    print(f"    Files loaded     : {sorted(evidence_map.keys())}")

    print(f"[*] Evaluating controls...")
    results = []
    for control in catalog:
        result = evaluate_control(control, evidence_map)
        results.append(result)
        icon = {
            "compliant":           "[PASS]",
            "partially-compliant": "[WARN]",
            "non-compliant":       "[FAIL]",
        }.get(result["status"], "[?]")
        print(f"    {icon}  {result['control_id']:6} {result['control_name']}")

    report      = build_report(results)
    report_path = save_report(report, args.output)
    print(f"\n[*] Report saved     : {report_path}")

    print_report(report)


if __name__ == "__main__":
    main()