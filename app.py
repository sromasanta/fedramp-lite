# app.py - Flask web server for the FedRAMP-Lite Compliance UI

import json
import os
import sys

from flask import Flask, jsonify, render_template, request

# Make sure the engine package is importable from this file's directory
sys.path.insert(0, os.path.dirname(__file__))

from engine.loader    import load_catalog, load_all_evidence
from engine.evaluator import evaluate_control
from engine.reporter  import build_report  # uncomment for save_report imported when needed **************

app = Flask(__name__)

CATALOG_PATH = os.path.join(os.path.dirname(__file__), "controls", "catalog.yaml")
REPORTS_DIR  = os.path.join(os.path.dirname(__file__), "reports")


# ── Helper: load catalog once ─────────────────────────────────────────────────

def get_catalog() -> list:
    return load_catalog(CATALOG_PATH)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main UI page."""
    return render_template("index.html")


@app.route("/api/catalog")
def catalog():
    """
    Return the full control catalog grouped by family.
    The UI uses this to build the family checkboxes and control list dynamically.

    Response shape:
    {
      "Access Control": [
        { "id": "AC-2", "name": "Account Management", "description": "..." },
        ...
      ],
      "Identification and Authentication": [ ... ]
    }
    """
    controls = get_catalog()
    grouped  = {}
    for ctrl in controls:
        family = ctrl.get("family", "Unknown")
        grouped.setdefault(family, []).append({
            "id":          ctrl["id"],
            "name":        ctrl["name"],
            "description": ctrl.get("description", "").strip(),
            "evidence_file": ctrl.get("evidence_file", "")
        })
    return jsonify(grouped)


@app.route("/api/evaluate", methods=["POST"])
def evaluate():
    """
    Receive evidence text + selected families, run the engine, return a report.

    Request JSON:
    {
        "families":      ["Access Control", "Identification and Authentication"],
        "evidence_text": "{ ... valid JSON ... }",
        "evidence_name": "users.json"
    }

    Response: the full compliance report dict (same shape as the JSON file report).
    """
    data = request.get_json(force=True)

    selected_families = data.get("families", [])
    evidence_text     = data.get("evidence_text", "").strip()
    evidence_name     = data.get("evidence_name", "evidence.json").strip()

    # ── Validate evidence input ───────────────────────────────────────────────
    if not evidence_text:
        return jsonify({"error": "No evidence provided."}), 400

    try:
        evidence_data = json.loads(evidence_text)
    except json.JSONDecodeError as exc:
        return jsonify({"error": f"Invalid JSON: {exc}"}), 400

    # ── Build evidence map keyed by filename stem ─────────────────────────────
    # e.g.  "users.json" -> key "users"
    evidence_key = os.path.splitext(evidence_name)[0]
    evidence_map = {evidence_key: evidence_data}

    # ── Filter catalog to selected families ───────────────────────────────────
    catalog  = get_catalog()
    filtered = [
        ctrl for ctrl in catalog
        if ctrl.get("family", "Unknown") in selected_families
    ]

    if not filtered:
        return jsonify({"error": "No controls matched the selected families."}), 400

    # ── Run the engine ────────────────────────────────────────────────────────
    results = [evaluate_control(ctrl, evidence_map) for ctrl in filtered]
    report  = build_report(results)

    # save_report(report, REPORTS_DIR)  # uncomment to persist reports to disk ********************

    return jsonify(report)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5000)
