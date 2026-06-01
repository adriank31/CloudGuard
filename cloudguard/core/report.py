"""
Report writers.

Takes the flat list of findings the engine produced and turns it into
something a human (Markdown) or another tool (JSON) can consume. Both formats
lead with the same summary block so the headline numbers are the first thing
you see either way.

We deliberately keep the two writers independent rather than rendering JSON
and then "prettifying" it - a Markdown report wants prose and tables, the JSON
wants machine-friendly structure, and trying to share one code path between
them just makes both worse.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from .findings import Finding, Severity, sort_findings, summarize


def _timestamp() -> str:
    # ISO 8601 in UTC. Reports get committed to repos and emailed around, so a
    # timezone-anchored stamp avoids the "wait, 3pm where?" problem.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_json(findings: List[Finding], provider: str, account: str) -> Dict[str, Any]:
    """Assemble the full report as a plain dict ready for json.dumps."""
    ordered = sort_findings(findings)
    return {
        "tool": "cloudguard",
        "generated_at": _timestamp(),
        "provider": provider,
        # `account` is whatever identifies the thing we scanned - an AWS account
        # id, an Azure subscription, a GCP project. Free text on purpose.
        "account": account,
        "summary": summarize(ordered),
        "findings": [f.to_dict() for f in ordered],
    }


def write_json(findings: List[Finding], provider: str, account: str) -> str:
    """Same as build_json but returns a pretty-printed string."""
    # indent=2 because these reports get read by people in PR reviews, not just
    # piped into jq. sort_keys stays off - we want our own field order, which
    # puts the summary before the findings.
    return json.dumps(build_json(findings, provider, account), indent=2)


# Small visual markers per severity. Plain text so they survive being pasted
# into a terminal, a GitHub issue, or a Slack message without turning to mojibake.
_SEVERITY_BADGE = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW: "[LOW]",
    Severity.INFO: "[INFO]",
}


def write_markdown(findings: List[Finding], provider: str, account: str) -> str:
    """Render a human-readable report. This is the default output."""
    ordered = sort_findings(findings)
    summary = summarize(ordered)
    counts = summary["counts_by_severity"]

    lines: List[str] = []

    # ---- Header -----------------------------------------------------------
    lines.append("# CloudGuard IAM Report")
    lines.append("")
    lines.append(f"- **Provider:** {provider}")
    lines.append(f"- **Account / scope:** {account}")
    lines.append(f"- **Generated:** {_timestamp()}")
    lines.append(f"- **Risk score:** {summary['risk_score']}")
    lines.append("")

    # ---- Summary table ----------------------------------------------------
    # A one-glance breakdown so a reviewer can triage before reading detail.
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in Severity:                       # iterate the enum to keep order fixed
        lines.append(f"| {sev.value} | {counts[sev.value]} |")
    lines.append(f"| **Total** | **{summary['total_findings']}** |")
    lines.append("")

    # Short-circuit on a clean run. An empty findings list is good news, and a
    # report that just says so reads better than an empty "Findings" heading.
    if not ordered:
        lines.append("No misconfigurations matched the active ruleset. ")
        lines.append("Either the account is in good shape or the ruleset needs widening.")
        lines.append("")
        return "\n".join(lines)

    # ---- Findings ---------------------------------------------------------
    lines.append("## Findings")
    lines.append("")
    for finding in ordered:
        badge = _SEVERITY_BADGE[finding.severity]
        # Each finding gets its own subsection. Rule id in the heading makes it
        # easy to grep the report or reference a specific item in a ticket.
        lines.append(f"### {badge} {finding.rule_id} - {finding.title}")
        lines.append("")
        lines.append(f"- **Resource:** `{finding.resource_id}`")
        lines.append(f"- **Type:** {finding.resource_type}")
        lines.append("")
        lines.append(finding.description)
        lines.append("")

        # Evidence renders as a fenced JSON block. People want to see the actual
        # offending value (the key age, the policy statement) without us having
        # to invent a bespoke layout for every check's evidence shape.
        if finding.evidence:
            lines.append("**Evidence**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(finding.evidence, indent=2, default=str))
            lines.append("```")
            lines.append("")

        lines.append(f"**Remediation:** {finding.remediation}")
        lines.append("")

        if finding.references:
            lines.append("**References:**")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")

    return "\n".join(lines)
