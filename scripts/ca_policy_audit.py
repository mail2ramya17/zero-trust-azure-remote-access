#!/usr/bin/env python3
"""Audit an export of Microsoft Entra Conditional Access policies against the
Zero Trust remote access baseline in this repository.

Input is the JSON returned by Microsoft Graph:

    GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies

for example exported with:

    az rest --method get \
      --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies \
      > policies.json

Usage:

    python scripts/ca_policy_audit.py policies.json \
        --break-glass <object-id> --break-glass <object-id> [--json]

Exit code is 1 when any FAIL finding is reported, so the script can gate a
pipeline that runs on a schedule against the live tenant.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

ENABLED = "enabled"
REPORT_ONLY = "enabledForReportingButNotEnforced"

PHISHING_RESISTANT_STRENGTH_ID = "00000000-0000-0000-0000-000000000004"

# Entra role template IDs this baseline treats as privileged.
PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
}

LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


@dataclass
class Finding:
    rule: str
    level: str  # PASS, WARN or FAIL
    message: str


def _users(policy: dict[str, Any]) -> dict[str, Any]:
    return (policy.get("conditions") or {}).get("users") or {}


def _apps(policy: dict[str, Any]) -> dict[str, Any]:
    return (policy.get("conditions") or {}).get("applications") or {}


def _client_types(policy: dict[str, Any]) -> set[str]:
    return set((policy.get("conditions") or {}).get("clientAppTypes") or [])


def _grant(policy: dict[str, Any]) -> dict[str, Any]:
    return policy.get("grantControls") or {}


def _builtin(policy: dict[str, Any]) -> set[str]:
    return set(_grant(policy).get("builtInControls") or [])


def _targets_all_users(policy: dict[str, Any]) -> bool:
    return "All" in (_users(policy).get("includeUsers") or [])


def _targets_all_apps(policy: dict[str, Any]) -> bool:
    return "All" in (_apps(policy).get("includeApplications") or [])


def _enforced(policies: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [p for p in policies if p.get("state") == ENABLED]


def check_mfa_all_users(policies: list[dict[str, Any]]) -> Finding:
    for p in _enforced(policies):
        if _targets_all_users(p) and _targets_all_apps(p) and (
            "mfa" in _builtin(p) or _grant(p).get("authenticationStrength")
        ):
            return Finding("ZT-01", "PASS", f"MFA for all users enforced by '{p.get('displayName')}'.")
    return Finding("ZT-01", "FAIL", "No enforced policy requires MFA for all users on all apps.")


def check_legacy_auth_blocked(policies: list[dict[str, Any]]) -> Finding:
    for p in _enforced(policies):
        if (
            _targets_all_users(p)
            and LEGACY_CLIENT_TYPES <= _client_types(p)
            and "block" in _builtin(p)
        ):
            return Finding("ZT-02", "PASS", f"Legacy authentication blocked by '{p.get('displayName')}'.")
    return Finding("ZT-02", "FAIL", "No enforced policy blocks legacy authentication for all users.")


def check_admin_phishing_resistant(policies: list[dict[str, Any]]) -> Finding:
    covered: set[str] = set()
    for p in _enforced(policies):
        strength = _grant(p).get("authenticationStrength") or {}
        if strength.get("id") != PHISHING_RESISTANT_STRENGTH_ID:
            continue
        if _targets_all_users(p):
            covered.update(PRIVILEGED_ROLES)
        covered.update(_users(p).get("includeRoles") or [])
    missing = [name for rid, name in PRIVILEGED_ROLES.items() if rid not in covered]
    if missing:
        return Finding(
            "ZT-03",
            "FAIL",
            "Phishing-resistant MFA not enforced for: " + ", ".join(sorted(missing)) + ".",
        )
    return Finding("ZT-03", "PASS", "Privileged roles require phishing-resistant MFA.")


def check_break_glass_excluded(
    policies: list[dict[str, Any]], break_glass: list[str]
) -> list[Finding]:
    if not break_glass:
        return [Finding("ZT-04", "WARN", "No emergency access accounts supplied; exclusion not checked.")]
    findings = []
    for p in policies:
        if p.get("state") not in (ENABLED, REPORT_ONLY):
            continue
        excluded = set(_users(p).get("excludeUsers") or [])
        missing = [bg for bg in break_glass if bg not in excluded]
        if missing:
            findings.append(
                Finding(
                    "ZT-04",
                    "FAIL",
                    f"'{p.get('displayName')}' does not exclude emergency account(s): {', '.join(missing)}.",
                )
            )
    if not findings:
        findings.append(Finding("ZT-04", "PASS", "Emergency access accounts excluded from every active policy."))
    return findings


def check_report_only(policies: list[dict[str, Any]]) -> list[Finding]:
    pending = [p.get("displayName", "<unnamed>") for p in policies if p.get("state") == REPORT_ONLY]
    if pending:
        return [
            Finding("ZT-05", "WARN", f"Policy in report-only, not enforced: '{name}'.")
            for name in pending
        ]
    return [Finding("ZT-05", "PASS", "No policies left in report-only.")]


def check_broad_exclusions(policies: list[dict[str, Any]], max_excluded_groups: int = 2) -> list[Finding]:
    findings = []
    for p in _enforced(policies):
        groups = _users(p).get("excludeGroups") or []
        if len(groups) > max_excluded_groups:
            findings.append(
                Finding(
                    "ZT-06",
                    "WARN",
                    f"'{p.get('displayName')}' excludes {len(groups)} groups; review for exclusion creep.",
                )
            )
    return findings or [Finding("ZT-06", "PASS", "No policy has broad group exclusions.")]


def audit(policies: list[dict[str, Any]], break_glass: list[str]) -> list[Finding]:
    findings = [
        check_mfa_all_users(policies),
        check_legacy_auth_blocked(policies),
        check_admin_phishing_resistant(policies),
    ]
    findings += check_break_glass_excluded(policies, break_glass)
    findings += check_report_only(policies)
    findings += check_broad_exclusions(policies)
    return findings


def load_policies(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("value", [])
    if not isinstance(data, list):
        raise ValueError("Expected a Graph response with a 'value' list or a bare list of policies.")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("export", type=Path, help="Graph JSON export of Conditional Access policies")
    parser.add_argument("--break-glass", action="append", default=[], help="Emergency account object ID")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    args = parser.parse_args(argv)

    findings = audit(load_policies(args.export), args.break_glass)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for f in findings:
            print(f"[{f.level:4}] {f.rule}  {f.message}")
        fails = sum(f.level == "FAIL" for f in findings)
        warns = sum(f.level == "WARN" for f in findings)
        print(f"\n{fails} failed, {warns} warnings, {len(findings) - fails - warns} passed")

    return 1 if any(f.level == "FAIL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
