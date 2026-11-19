import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import ca_policy_audit as audit  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
BREAK_GLASS = [
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
]


def load(name):
    return audit.load_policies(FIXTURES / name)


def levels(findings, rule):
    return {f.level for f in findings if f.rule == rule}


def test_compliant_baseline_has_no_failures():
    findings = audit.audit(load("baseline_compliant.json"), BREAK_GLASS)
    assert not [f for f in findings if f.level == "FAIL"]


@pytest.mark.parametrize("rule", ["ZT-01", "ZT-02", "ZT-03", "ZT-04"])
def test_gap_baseline_fails_core_rules(rule):
    findings = audit.audit(load("baseline_gaps.json"), BREAK_GLASS)
    assert "FAIL" in levels(findings, rule)


def test_report_only_policy_is_not_counted_as_enforced():
    findings = audit.audit(load("baseline_gaps.json"), BREAK_GLASS)
    assert "WARN" in levels(findings, "ZT-05")
    assert levels(findings, "ZT-01") == {"FAIL"}


def test_broad_group_exclusions_are_flagged():
    findings = audit.audit(load("baseline_gaps.json"), BREAK_GLASS)
    assert "WARN" in levels(findings, "ZT-06")


def test_missing_break_glass_list_warns():
    findings = audit.audit(load("baseline_compliant.json"), [])
    assert levels(findings, "ZT-04") == {"WARN"}


def test_cli_exit_codes(capsys):
    ok = audit.main([str(FIXTURES / "baseline_compliant.json"),
                     "--break-glass", BREAK_GLASS[0], "--break-glass", BREAK_GLASS[1]])
    assert ok == 0
    capsys.readouterr()

    bad = audit.main([str(FIXTURES / "baseline_gaps.json"), "--json"])
    assert bad == 1
    report = json.loads(capsys.readouterr().out)
    assert {"rule", "level", "message"} <= set(report[0])


def test_accepts_bare_list(tmp_path):
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(json.loads((FIXTURES / "baseline_compliant.json").read_text())["value"]))
    assert len(audit.load_policies(path)) == 3
