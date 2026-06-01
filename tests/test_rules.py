"""
Tests for the rule engine and reporting.

These run entirely offline - no cloud, no network - by feeding the engine the
same normalised resource dicts a provider would produce. That's the whole point
of the normalisation boundary: the interesting logic is testable without ever
touching AWS, Azure or GCP.

Run with:  python -m pytest   (or just  pytest)  from the project root.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudguard.core import RuleEngine, Severity, load_rules, write_json, write_markdown
from cloudguard.core.findings import summarize


# Path to the bundled rules so the tests exercise the real shipped ruleset
# rather than a parallel copy that could drift out of sync.
RULES_DIR = Path(__file__).resolve().parents[1] / "cloudguard" / "rules"


def _engine(provider: str) -> RuleEngine:
    """Build an engine loaded with just one provider's rules."""
    return RuleEngine(load_rules(RULES_DIR, provider=provider))


def test_rules_load_without_error():
    # If any YAML file is malformed or a check name is fat-fingered, loading the
    # whole directory is where it surfaces. A clean load across all providers is
    # a cheap but meaningful smoke test.
    rules = load_rules(RULES_DIR)
    assert len(rules) > 0
    # Every rule id has to be unique - load_rules enforces it, but assert here
    # too so a regression in that guard gets caught by the suite.
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_admin_without_mfa_flags_only_the_bad_user():
    # Two users: one is an admin with no MFA (should fire), the other is an
    # admin who *does* have MFA (should not). This pins down that the check
    # looks at both conditions, not just the admin flag.
    resources = {
        "iam_user": [
            {"name": "danger", "arn": "arn:aws:iam::1:user/danger",
             "has_admin": True, "mfa_enabled": False, "admin_source": "AdministratorAccess (managed)"},
            {"name": "safe", "arn": "arn:aws:iam::1:user/safe",
             "has_admin": True, "mfa_enabled": True, "admin_source": "AdministratorAccess (managed)"},
        ]
    }
    findings = _engine("aws").run(resources)
    admin_findings = [f for f in findings if f.rule_id == "AWS_IAM_001"]
    assert len(admin_findings) == 1
    assert admin_findings[0].resource_id == "arn:aws:iam::1:user/danger"
    assert admin_findings[0].severity == Severity.CRITICAL


def test_wildcard_policy_check():
    # An Allow on *:* should fire; a scoped Allow (full actions but only one
    # bucket) should not. Catches the easy mistake of flagging any "*" action.
    resources = {
        "policy_statement": [
            {"policy_name": "wide-open", "attached_to": "arn:...", "effect": "Allow",
             "document": {"Effect": "Allow", "Action": "*", "Resource": "*"}},
            {"policy_name": "scoped", "attached_to": "arn:...", "effect": "Allow",
             "document": {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}},
        ]
    }
    findings = _engine("aws").run(resources)
    wildcard = [f for f in findings if f.rule_id == "AWS_IAM_002"]
    assert len(wildcard) == 1
    assert wildcard[0].resource_id == "wide-open"


def test_access_key_age_threshold():
    # 120 days is over the 90-day threshold and should fire; 30 days should not.
    # This is the declarative `gt` path, so it also proves the YAML-driven
    # matcher works end to end.
    resources = {
        "access_key": [
            {"id": "AKIAOLD", "user": "bob", "status": "Active", "age_days": 120},
            {"id": "AKIANEW", "user": "bob", "status": "Active", "age_days": 30},
        ]
    }
    findings = _engine("aws").run(resources)
    aged = [f for f in findings if f.rule_id == "AWS_IAM_003"]
    assert len(aged) == 1
    assert aged[0].resource_id == "AKIAOLD"


def test_gcp_public_member_escalates_on_primitive_role():
    # allUsers on a primitive role should escalate to critical; allUsers on a
    # narrow role stays high. Proves the severity-bump branch in the check.
    resources = {
        "iam_binding": [
            {"id": "b1", "role": "roles/owner", "member": "allUsers",
             "member_type": "allUsers", "is_primitive_role": True, "is_public": True},
            {"id": "b2", "role": "roles/pubsub.publisher", "member": "allAuthenticatedUsers",
             "member_type": "allAuthenticatedUsers", "is_primitive_role": False, "is_public": True},
        ]
    }
    findings = _engine("gcp").run(resources)
    public = {f.resource_id: f for f in findings if f.rule_id == "GCP_IAM_001"}
    assert len(public) == 2
    assert public["roles/owner -> allUsers"].severity == Severity.CRITICAL
    assert public["roles/pubsub.publisher -> allAuthenticatedUsers"].severity == Severity.HIGH


def test_summary_counts_and_score():
    # A known mix of findings should produce predictable counts and a score that
    # is just the sum of the per-severity weights (40 + 8 = 48 here).
    resources = {
        "iam_user": [
            {"name": "danger", "arn": "arn:1", "has_admin": True, "mfa_enabled": False,
             "admin_source": "managed"},
        ],
        "access_key": [
            {"id": "AKIAOLD", "user": "danger", "status": "Active", "age_days": 200},
        ],
    }
    findings = _engine("aws").run(resources)
    summary = summarize(findings)
    assert summary["counts_by_severity"]["critical"] == 1   # admin no MFA
    assert summary["counts_by_severity"]["medium"] == 1      # old key
    assert summary["risk_score"] == Severity.CRITICAL.weight + Severity.MEDIUM.weight


def test_reports_render_for_empty_and_nonempty():
    # The reporters shouldn't blow up on either an empty result set or a
    # populated one. Cheap guard against a formatting bug that only shows up
    # when there's (no) data.
    empty = write_markdown([], "aws", "acct-1")
    assert "No misconfigurations" in empty

    resources = {"access_key": [{"id": "AKIAOLD", "user": "x", "status": "Active", "age_days": 200}]}
    findings = _engine("aws").run(resources)
    md = write_markdown(findings, "aws", "acct-1")
    assert "AWS_IAM_003" in md
    js = write_json(findings, "aws", "acct-1")
    assert "AWS_IAM_003" in js
