"""
loader.py
---------
Reads evidence files from disk and the control catalog.

Supports:
  .json  -> loaded as a Python dict directly
  .yaml  -> loaded as a Python dict
  .csv   -> converted to { "rows": [ {col: val}, ... ] }

The evaluator always receives a plain dict, regardless of source format.
"""

import json
import csv
import os
import yaml


def load_evidence(filepath: str) -> dict:
    """
    Load a single evidence file by path.
    Detects format from extension and returns a Python dict.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Evidence file not found: {filepath}")

    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".json":
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    elif ext in (".yaml", ".yml"):
        with open(filepath, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    elif ext == ".csv":
        # CSV has no natural dict shape, so we wrap rows in a key
        rows = []
        with open(filepath, "r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                rows.append(dict(row))
        return {"rows": rows}

    else:
        raise ValueError(f"Unsupported evidence format '{ext}': {filepath}")


def load_all_evidence(evidence_dir: str) -> dict:
    """
    Load every supported file from an evidence directory.

    Returns a dict keyed by filename without extension:
        { "users": {...}, "firewall": {...} }

    The catalog references evidence by filename (e.g. "users.json"),
    so the evaluator strips the extension to do the lookup.
    """
    supported = {".json", ".yaml", ".yml", ".csv"}
    evidence_map = {}

    for fname in os.listdir(evidence_dir):
        ext = os.path.splitext(fname)[1].lower()
        if ext not in supported:
            continue
        key = os.path.splitext(fname)[0]           # "users.json" -> "users"
        evidence_map[key] = load_evidence(os.path.join(evidence_dir, fname))

    return evidence_map


def load_catalog(filepath: str) -> list:
    """
    Load the YAML control catalog.
    Returns the list of control definition dicts.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Catalog not found: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data.get("controls", [])