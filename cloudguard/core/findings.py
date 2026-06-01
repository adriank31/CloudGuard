"""
Data model for everything the scanner produces.

Two ideas live in here:

  1. Severity - a small ordered enum. We need ordering (and numeric weight)
     so we can sort findings worst-first and roll them up into a single
     account risk score later on.

  2. Finding - one record per problem we spot. Every check in the engine
     ends up producing zero or more of these. Keeping them as plain
     dataclasses means they serialize to JSON without any fuss and they're
     trivial to assert against in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    # The string value is what shows up in reports and YAML rule files, so
    # keep these lowercase - that's what people will type in their rules.
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        # Used for the overall risk score. The gap between critical and high
        # is deliberately wide - one unauthenticated admin is worse than a
        # pile of low-severity hygiene nits, and the score should reflect that.
        return {
            "critical": 40,
            "high": 20,
            "medium": 8,
            "low": 3,
            "info": 0,
        }[self.value]

    @property
    def rank(self) -> int:
        # Lower rank == more severe. This is the key we sort on so the nastiest
        # stuff floats to the top of the report.
        order = ["critical", "high", "medium", "low", "info"]
        return order.index(self.value)

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        # Rule authors write severities as free text in YAML. Be forgiving
        # about whitespace and case so a stray "  High " doesn't break a load.
        cleaned = (value or "").strip().lower()
        for member in cls:
            if member.value == cleaned:
                return member
        # If someone typos a severity we'd rather surface a loud error at load
        # time than silently drop the rule and under-report risk.
        raise ValueError(f"unknown severity: {value!r}")


@dataclass
class Finding:
    """One concrete problem tied to one specific resource."""

    rule_id: str                 # e.g. AWS_IAM_001 - matches the id in the YAML
    title: str                   # short human-readable summary
    severity: Severity
    provider: str                # aws | azure | gcp
    resource_type: str           # iam_user, role_assignment, iam_binding, ...
    resource_id: str             # the thing that's actually misconfigured
    description: str             # why this is a problem
    remediation: str             # what to do about it

    # Evidence is whatever made us flag this - the access key age, the offending
    # policy statement, etc. It's free-form on purpose because every check cares
    # about different details, and we just dump it into the report verbatim.
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Optional pointers to docs / CIS benchmark items. Handy in a report but
    # nothing downstream depends on them, so they default to empty.
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        # asdict() walks the whole dataclass for us. The only thing it can't
        # handle is the Severity enum, so we flatten that back to its string.
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Worst-first, then alphabetical by rule id so the order is stable."""
    # Stable secondary sort on rule_id keeps two runs producing identical
    # output, which matters if anyone diffs reports between scans.
    return sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.resource_id))


def summarize(findings: List[Finding]) -> Dict[str, Any]:
    """Roll a list of findings up into headline numbers for the report top."""
    counts: Dict[str, int] = {s.value: 0 for s in Severity}
    score = 0
    for finding in findings:
        counts[finding.severity.value] += 1
        score += finding.severity.weight

    return {
        "total_findings": len(findings),
        "counts_by_severity": counts,
        # Raw additive score. It's intentionally unbounded - a worse account
        # should always score higher, we're not normalising to 0-100 because
        # that hides how bad a truly terrible account is.
        "risk_score": score,
    }
