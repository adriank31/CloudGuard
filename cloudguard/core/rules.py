"""
The rule engine.

A rule is just a chunk of YAML describing one thing we want to catch. There
are two flavours:

  * Declarative rules carry a `match:` block - a field, an operator and a
    value. The engine walks every resource of the rule's `resource_type` and
    emits a finding wherever the comparison holds. No Python required, which
    means an analyst can add coverage by editing YAML alone.

  * Check rules carry a `check:` name instead. Those hand off to a function in
    checks.py for logic that's too gnarly to express as one comparison.

A single rule uses one flavour or the other, never both. Mixing them would
make the precedence ambiguous, so the loader rejects it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .checks import get_check
from .findings import Finding, Severity


# Supported comparison operators for declarative `match` blocks. Keeping the
# implementations as tiny lambdas in one table makes the set of allowed
# operators obvious at a glance and easy to extend.
_OPERATORS = {
    "eq": lambda actual, expected: actual == expected,
    "ne": lambda actual, expected: actual != expected,
    "gt": lambda actual, expected: actual is not None and actual > expected,
    "gte": lambda actual, expected: actual is not None and actual >= expected,
    "lt": lambda actual, expected: actual is not None and actual < expected,
    "lte": lambda actual, expected: actual is not None and actual <= expected,
    # `in` checks membership of actual within an expected list/set.
    "in": lambda actual, expected: actual in expected,
    # `contains` is the mirror image - does the actual collection hold expected?
    "contains": lambda actual, expected: expected in (actual or []),
    # `exists` ignores the value entirely and just asks whether the field is set.
    "exists": lambda actual, expected: (actual is not None) == bool(expected),
    # regex match against a stringified field, handy for ARNs and emails.
    "regex": lambda actual, expected: bool(re.search(expected, str(actual or ""))),
}


@dataclass
class Rule:
    """One loaded rule. Mirrors the YAML keys almost one-to-one."""

    id: str
    title: str
    severity: Severity
    provider: str
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)

    # Exactly one of these two is populated depending on the rule flavour.
    resource_type: Optional[str] = None      # required for declarative rules
    match: Optional[Dict[str, Any]] = None    # the field/op/value comparison
    check: Optional[str] = None               # name of a function in checks.py

    @property
    def is_declarative(self) -> bool:
        return self.match is not None


def _parse_rule(raw: Dict[str, Any], source: Path) -> Rule:
    """Turn one YAML mapping into a Rule, shouting clearly if it's malformed."""
    # We fail loudly on missing required keys. A half-defined rule that silently
    # does nothing is the worst outcome for a security tool - you'd think you
    # had coverage you didn't.
    required = ("id", "title", "severity", "provider", "description", "remediation")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError(
            f"rule in {source.name} is missing required keys: {', '.join(missing)}"
        )

    has_match = "match" in raw
    has_check = "check" in raw
    # The two flavours are mutually exclusive. Catch the mistake here rather
    # than picking one arbitrarily at evaluation time.
    if has_match and has_check:
        raise ValueError(f"rule {raw['id']} defines both 'match' and 'check' - pick one")
    if not has_match and not has_check:
        raise ValueError(f"rule {raw['id']} defines neither 'match' nor 'check'")

    # Declarative rules can't work without knowing which resource list to walk.
    if has_match and "resource_type" not in raw:
        raise ValueError(f"rule {raw['id']} uses 'match' but has no 'resource_type'")

    return Rule(
        id=raw["id"],
        title=raw["title"],
        severity=Severity.from_string(raw["severity"]),
        provider=raw["provider"],
        description=raw["description"].strip(),
        remediation=raw["remediation"].strip(),
        references=raw.get("references", []),
        resource_type=raw.get("resource_type"),
        match=raw.get("match"),
        check=raw.get("check"),
    )


def load_rules(path: Path, provider: Optional[str] = None) -> List[Rule]:
    """Read every *.yaml under `path` and return the parsed rules.

    `path` can be a single file or a directory. If a provider is given we only
    keep rules tagged for that provider, which is how `--provider aws` ends up
    ignoring the Azure and GCP rule files.
    """
    path = Path(path)
    files: List[Path] = []
    if path.is_dir():
        # Sorted so load order is deterministic - again, nice for diffing.
        files = sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml"))
    else:
        files = [path]

    rules: List[Rule] = []
    seen_ids: set = set()
    for file in files:
        # An empty YAML file parses to None, so coalesce to an empty list.
        documents = yaml.safe_load(file.read_text()) or []
        for raw in documents:
            rule = _parse_rule(raw, file)
            # Duplicate rule ids would make findings ambiguous and break any
            # downstream dedupe keyed on rule_id, so reject them outright.
            if rule.id in seen_ids:
                raise ValueError(f"duplicate rule id {rule.id!r} found in {file.name}")
            seen_ids.add(rule.id)
            if provider is None or rule.provider == provider:
                rules.append(rule)
    return rules


def _resolve_field(resource: Dict[str, Any], dotted: str) -> Any:
    """Read a possibly-nested field out of a resource using dotted notation.

    So `metadata.region` digs into resource["metadata"]["region"]. Returns None
    the moment any hop is missing rather than raising, because a missing field
    just means "this rule doesn't apply", not "the scan is broken".
    """
    current: Any = resource
    for part in dotted.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _evaluate_match(rule: Rule, resources: Dict[str, List[dict]]) -> List[Finding]:
    """Run a declarative rule against the relevant resource list."""
    spec = rule.match or {}
    field_name = spec.get("field")
    op_name = spec.get("op", "eq")
    expected = spec.get("value")

    operator = _OPERATORS.get(op_name)
    if operator is None:
        # Bad operator is an authoring error - name the valid ones so it's a
        # one-line fix rather than a guessing game.
        valid = ", ".join(sorted(_OPERATORS))
        raise ValueError(f"rule {rule.id} uses unknown operator {op_name!r}. valid: {valid}")

    findings: List[Finding] = []
    for resource in resources.get(rule.resource_type, []):
        actual = _resolve_field(resource, field_name)
        if operator(actual, expected):
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    provider=rule.provider,
                    resource_type=rule.resource_type,
                    # Prefer a stable id field if the resource carries one,
                    # otherwise fall back to the field we matched on so the
                    # finding still points at something concrete.
                    resource_id=str(
                        resource.get("id")
                        or resource.get("name")
                        or resource.get("arn")
                        or actual
                    ),
                    description=rule.description,
                    remediation=rule.remediation,
                    # Stash the field and its value so the report shows *why*
                    # we flagged it, not just that we did.
                    evidence={field_name: actual, "matched_op": op_name, "threshold": expected},
                    references=rule.references,
                )
            )
    return findings


class RuleEngine:
    """Holds a set of rules and runs them over collected resources."""

    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def run(self, resources: Dict[str, List[dict]]) -> List[Finding]:
        """Evaluate every rule and return the flat list of findings."""
        findings: List[Finding] = []
        for rule in self.rules:
            if rule.is_declarative:
                findings.extend(_evaluate_match(rule, resources))
            else:
                # Named check: look the function up and hand it the whole
                # resource bag plus the rule (for metadata like severity/title).
                func = get_check(rule.check)
                findings.extend(func(resources, rule))
        return findings
