"""
evaluator.py
------------
The compliance logic engine.

For each control it:
  1. Fetches the matching evidence
  2. Runs every check defined in the catalog rule
  3. Collects pass/fail findings
  4. Rolls up to: compliant / partially-compliant / non-compliant

Check types implemented (all user-account focused)
───────────────────────────────────────────────────
no_inactive_over_days     ANY account with last_login > N days is stale; disabled accounts still present are flagged
all_have_field            Every account object must contain a named field
privileged_accounts_reviewed  All privileged=true accounts must have access_reviewed=true
not_all_privileged        At least one account must be non-privileged (separation of duties)
privileged_require_mfa    Every privileged account must have mfa_enabled=true
no_inactive_privileged    No inactive account should have privileged=true
password_age_within_limit Active accounts must have password_age_days <= max_days
all_active_have_mfa       Every active account must have mfa_enabled=true
"""

from __future__ import annotations
from typing import Any


# ── Public entry point ────────────────────────────────────────────────────────

def evaluate_control(control: dict, evidence_map: dict) -> dict:
    """
    Evaluate one control against loaded evidence.

    Returns:
    {
        "control_id":    "AC-2",
        "control_name":  "Account Management",
        "family":        "Access Control",
        "status":        "compliant" | "partially-compliant" | "non-compliant",
        "findings":      [ {"check": "...", "passed": bool, "detail": "..."}, ... ],
        "evidence_used": "users.json",
        "error":         None | "message"
    }
    """
    control_id   = control["id"]
    control_name = control["name"]
    family       = control.get("family", "Unknown")
    evidence_key = control.get("evidence_file", "").rsplit(".", 1)[0]  # strip extension

    # ── Locate the evidence ───────────────────────────────────────────────────
    if evidence_key not in evidence_map:
        return _error_result(
            control_id, control_name, family,
            control.get("evidence_file", "?"),
            f"Evidence file '{control.get('evidence_file')}' not found."
        )

    evidence = evidence_map[evidence_key]
    findings: list[dict] = []

    # ── Run every rule / check ────────────────────────────────────────────────
    for rule in control.get("rules", []):
        field_name  = rule["field"]
        field_value = evidence.get(field_name)

        for check in rule.get("checks", []):
            finding = _run_check(check, field_name, field_value)
            findings.append(finding)

    return {
        "control_id":    control_id,
        "control_name":  control_name,
        "family":        family,
        "status":        _rollup(findings),
        "findings":      findings,
        "evidence_used": control.get("evidence_file", "unknown"),
        "error":         None,
    }


# ── Check dispatcher ──────────────────────────────────────────────────────────

def _run_check(check: dict, field_name: str, field_value: Any) -> dict:
    """Route to the correct check function based on 'type'."""
    check_type = check.get("type", "unknown")

    try:
        if check_type == "no_inactive_over_days":
            return _no_inactive_over_days(
                field_name, field_value,
                check["days"], check["status_field"], check["flag_field"]
            )

        elif check_type == "all_have_field":
            return _all_have_field(field_name, field_value, check["field"])

        elif check_type == "privileged_accounts_reviewed":
            return _privileged_accounts_reviewed(field_name, field_value)

        elif check_type == "not_all_privileged":
            return _not_all_privileged(field_name, field_value)

        elif check_type == "privileged_require_mfa":
            return _privileged_require_mfa(field_name, field_value)

        elif check_type == "no_inactive_privileged":
            return _no_inactive_privileged(
                field_name, field_value, check["flag_field"]
            )

        elif check_type == "password_age_within_limit":
            return _password_age_within_limit(
                field_name, field_value,
                check["max_days"], check["flag_field"]
            )

        elif check_type == "all_active_have_mfa":
            return _all_active_have_mfa(
                field_name, field_value,
                check["flag_field"], check["mfa_field"]
            )

        else:
            return _finding(check_type, False,
                            f"Unknown check type '{check_type}' — not implemented.")

    except Exception as exc:
        return _finding(check_type, False, f"Check error: {exc}")


# ── Check implementations ─────────────────────────────────────────────────────

def _no_inactive_over_days(
    field: str, accounts: Any,
    max_days: int, status_field: str, flag_field: str
) -> dict:
    """
    AC-2: Two separate sub-checks rolled into one finding:
      1. ANY account (active or not) with last_login_days_ago > max_days is stale.
         A real user logging in resets this. 500 days with active=True is still a gap.
      2. Accounts marked active=False are disabled — they should have near-zero
         last_login_days_ago OR be removed entirely.
    Both types of violations are reported together.
    """
    if not isinstance(accounts, list):
        return _finding("no_inactive_over_days", False, f"'{field}' is not a list.")

    # Check 1: any account whose last login exceeds the threshold
    stale_login = [
        f"{acct.get('username','?')} ({acct.get(status_field, '?')}d)"
        for acct in accounts
        if acct.get(status_field, 0) > max_days
    ]

    # Check 2: accounts flagged inactive but still present in the system
    still_present_inactive = [
        acct.get("username", "?")
        for acct in accounts
        if not acct.get(flag_field, True)
    ]

    violations = []
    if stale_login:
        violations.append(f"Accounts with no login in >{max_days} days: {stale_login}")
    if still_present_inactive:
        violations.append(f"Disabled accounts still present in system: {still_present_inactive}")

    passed = len(violations) == 0
    detail = (
        " | ".join(violations)
        if not passed
        else f"All accounts have logged in within {max_days} days and no disabled accounts exist [OK]"
    )
    return _finding("no_inactive_over_days", passed, detail)


def _all_have_field(field: str, accounts: Any, required_field: str) -> dict:
    """
    AC-2 / AC-3: Every account object must contain the named field.
    Catches accounts created without a role assigned.
    """
    if not isinstance(accounts, list):
        return _finding("all_have_field", False, f"'{field}' is not a list.")

    missing = [
        acct.get("username", "?")
        for acct in accounts
        if required_field not in acct
    ]

    passed = len(missing) == 0
    detail = (
        f"Accounts missing '{required_field}' field: {missing}"
        if not passed
        else f"All accounts have the '{required_field}' field assigned [OK]"
    )
    return _finding(f"all_have_field:{required_field}", passed, detail)


def _privileged_accounts_reviewed(field: str, accounts: Any) -> dict:
    """
    AC-3: Every account with privileged=True must also have access_reviewed=True.
    Privileged access without a completed review is a control gap.
    """
    if not isinstance(accounts, list):
        return _finding("privileged_accounts_reviewed", False,
                        f"'{field}' is not a list.")

    not_reviewed = [
        acct.get("username", "?")
        for acct in accounts
        if acct.get("privileged", False) and not acct.get("access_reviewed", False)
    ]

    passed = len(not_reviewed) == 0
    detail = (
        f"Privileged accounts without completed access review: {not_reviewed}"
        if not passed
        else "All privileged accounts have completed access reviews [OK]"
    )
    return _finding("privileged_accounts_reviewed", passed, detail)


def _not_all_privileged(field: str, accounts: Any) -> dict:
    """
    AC-5: Separation of duties — not every account should be privileged.
    If 100% of accounts are admins/privileged, there is no separation of duties.
    """
    if not isinstance(accounts, list):
        return _finding("not_all_privileged", False, f"'{field}' is not a list.")

    total      = len(accounts)
    privileged = sum(1 for a in accounts if a.get("privileged", False))

    passed = privileged < total
    detail = (
        f"All {total} accounts are privileged — no separation of duties."
        if not passed
        else f"{privileged} of {total} accounts are privileged - separation of duties maintained [OK]"
    )
    return _finding("not_all_privileged", passed, detail)


def _privileged_require_mfa(field: str, accounts: Any) -> dict:
    """
    AC-6 / IA-2: Every account with privileged=True must have mfa_enabled=True.
    Privileged access without MFA is a high-severity gap in FedRAMP 20x.
    """
    if not isinstance(accounts, list):
        return _finding("privileged_require_mfa", False, f"'{field}' is not a list.")

    no_mfa = [
        acct.get("username", "?")
        for acct in accounts
        if acct.get("privileged", False) and not acct.get("mfa_enabled", False)
    ]

    passed = len(no_mfa) == 0
    detail = (
        f"Privileged accounts without MFA: {no_mfa}"
        if not passed
        else "All privileged accounts have MFA enabled [OK]"
    )
    return _finding("privileged_require_mfa", passed, detail)


def _no_inactive_privileged(field: str, accounts: Any, flag_field: str) -> dict:
    """
    AC-6: No inactive account should retain privileged access.
    An inactive admin account is an unnecessary standing privilege.
    """
    if not isinstance(accounts, list):
        return _finding("no_inactive_privileged", False, f"'{field}' is not a list.")

    violators = [
        acct.get("username", "?")
        for acct in accounts
        if not acct.get(flag_field, True) and acct.get("privileged", False)
    ]

    passed = len(violators) == 0
    detail = (
        f"Inactive accounts with privileged access: {violators}"
        if not passed
        else "No inactive accounts retain privileged access [OK]"
    )
    return _finding("no_inactive_privileged", passed, detail)


def _password_age_within_limit(
    field: str, accounts: Any, max_days: int, flag_field: str
) -> dict:
    """
    AC-11: Active accounts must have passwords rotated within max_days.
    Stale passwords on active accounts indicate weak credential hygiene.
    """
    if not isinstance(accounts, list):
        return _finding("password_age_within_limit", False, f"'{field}' is not a list.")

    violators = [
        f"{acct.get('username','?')} ({acct.get('password_age_days','?')}d)"
        for acct in accounts
        if acct.get(flag_field, True)                      # only active accounts
        and acct.get("password_age_days", 0) > max_days
    ]

    passed = len(violators) == 0
    detail = (
        f"Active accounts with passwords older than {max_days} days: {violators}"
        if not passed
        else f"All active accounts have passwords within the {max_days}-day limit [OK]"
    )
    return _finding(f"password_age_within_limit:{max_days}d", passed, detail)


def _all_active_have_mfa(
    field: str, accounts: Any, flag_field: str, mfa_field: str
) -> dict:
    """
    IA-2: Every active account must have MFA enabled.
    This is a primary FedRAMP 20x authentication requirement.
    """
    if not isinstance(accounts, list):
        return _finding("all_active_have_mfa", False, f"'{field}' is not a list.")

    no_mfa = [
        acct.get("username", "?")
        for acct in accounts
        if acct.get(flag_field, True) and not acct.get(mfa_field, False)
    ]

    passed = len(no_mfa) == 0
    detail = (
        f"Active accounts without MFA enabled: {no_mfa}"
        if not passed
        else "All active accounts have MFA enabled [OK]"
    )
    return _finding("all_active_have_mfa", passed, detail)


# ── Rollup ────────────────────────────────────────────────────────────────────

def _rollup(findings: list[dict]) -> str:
    """
    compliant           — every check passed
    partially-compliant — some passed, some failed
    non-compliant       — all checks failed, or no findings
    """
    if not findings:
        return "non-compliant"

    passed = sum(1 for f in findings if f["passed"])
    total  = len(findings)

    if passed == total:
        return "compliant"
    elif passed == 0:
        return "non-compliant"
    else:
        return "partially-compliant"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(check_id: str, passed: bool, detail: str) -> dict:
    return {"check": check_id, "passed": passed, "detail": detail}


def _error_result(
    control_id: str, control_name: str, family: str,
    evidence_file: str, message: str
) -> dict:
    return {
        "control_id":    control_id,
        "control_name":  control_name,
        "family":        family,
        "status":        "non-compliant",
        "findings":      [],
        "evidence_used": evidence_file,
        "error":         message,
    }