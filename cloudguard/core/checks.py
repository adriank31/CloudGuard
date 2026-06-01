"""
Named checks.

Most rules in this tool are dead simple: look at a field on a resource and
compare it to a value (is this access key older than 90 days?). That kind of
thing lives entirely in the YAML and gets handled by the declarative matcher
in rules.py.

But some misconfigurations need real logic - cross-referencing two resources,
parsing a policy document, that sort of thing. Those can't be squeezed into a
single field comparison, so we write them as Python functions here and let a
rule reference one by name with `check: <name>`.

The registry pattern keeps this clean: decorate a function with @check("name")
and the engine can find it later without anybody maintaining a giant if/elif.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from .findings import Finding, Severity


# name -> function. Populated by the @check decorator at import time.
_REGISTRY: Dict[str, Callable] = {}


def check(name: str) -> Callable:
    """Decorator that files a function under `name` in the registry."""
    def register(func: Callable) -> Callable:
        # Guard against two checks claiming the same name - that's almost always
        # a copy/paste mistake and would otherwise silently shadow one of them.
        if name in _REGISTRY:
            raise ValueError(f"duplicate check name: {name!r}")
        _REGISTRY[name] = func
        return func
    return register


def get_check(name: str) -> Callable:
    """Look up a check by name, with a useful error if a rule typos it."""
    if name not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise KeyError(f"no check named {name!r}. registered checks: {known}")
    return _REGISTRY[name]


# ---------------------------------------------------------------------------
# Helpers shared by the checks below.
# ---------------------------------------------------------------------------

def _statement_actions(statement: Dict[str, Any]) -> List[str]:
    """Pull the Action field out of an IAM statement as a flat list.

    IAM is annoyingly flexible here: Action can be a single string or a list,
    and the key might be `Action` (allow) or `NotAction`. We fold all of that
    into one list so callers never have to special-case it.
    """
    actions: List[str] = []
    for key in ("Action", "NotAction"):
        value = statement.get(key)
        if value is None:
            continue
        # A lone "iam:PassRole" comes back as a str; a real policy is a list.
        if isinstance(value, str):
            actions.append(value)
        else:
            actions.extend(value)
    return actions


def _statement_resources(statement: Dict[str, Any]) -> List[str]:
    """Same normalisation trick as above, but for the Resource field."""
    resources: List[str] = []
    for key in ("Resource", "NotResource"):
        value = statement.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            resources.append(value)
        else:
            resources.extend(value)
    return resources


# ---------------------------------------------------------------------------
# AWS checks
# ---------------------------------------------------------------------------

@check("aws_admin_without_mfa")
def aws_admin_without_mfa(resources: Dict[str, List[dict]], rule: Any) -> List[Finding]:
    """Flag any IAM user that has admin-level access but no MFA device.

    This is the single scariest IAM finding in most accounts: a password-only
    login that can do anything. We treat "admin" as either the AWS-managed
    AdministratorAccess policy or any attached statement that grants *:* .
    """
    findings: List[Finding] = []
    for user in resources.get("iam_user", []):
        # `has_admin` is computed by the provider while it walks the policies,
        # so the heavy lifting already happened - we just read the flag here.
        if user.get("has_admin") and not user.get("mfa_enabled"):
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    provider="aws",
                    resource_type="iam_user",
                    resource_id=user.get("arn") or user.get("name", "<unknown>"),
                    description=rule.description,
                    remediation=rule.remediation,
                    evidence={
                        "user": user.get("name"),
                        "mfa_enabled": user.get("mfa_enabled"),
                        "admin_source": user.get("admin_source"),
                    },
                    references=rule.references,
                )
            )
    return findings


@check("aws_wildcard_policy")
def aws_wildcard_policy(resources: Dict[str, List[dict]], rule: Any) -> List[Finding]:
    """Flag policy statements that allow every action on every resource.

    `"Action": "*"` with `"Resource": "*"` and `"Effect": "Allow"` is the
    textbook over-grant. It shows up constantly in hand-rolled inline policies
    where someone "just wanted it to work" and never tightened it back down.
    """
    findings: List[Finding] = []
    for statement in resources.get("policy_statement", []):
        # We only care about Allow - a wildcard Deny is actually fine (and
        # sometimes a deliberate guardrail), so skip those.
        if statement.get("effect") != "Allow":
            continue

        actions = _statement_actions(statement.get("document", {}))
        resource_arns = _statement_resources(statement.get("document", {}))

        # A bare "*" in both lists is the dangerous combination. Checking both
        # avoids flagging a scoped admin (full actions but only on one bucket).
        if "*" in actions and "*" in resource_arns:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    provider="aws",
                    resource_type="policy_statement",
                    resource_id=statement.get("policy_name", "<inline>"),
                    description=rule.description,
                    remediation=rule.remediation,
                    evidence={
                        "policy_name": statement.get("policy_name"),
                        "attached_to": statement.get("attached_to"),
                        "statement": statement.get("document"),
                    },
                    references=rule.references,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# GCP checks
# ---------------------------------------------------------------------------

@check("gcp_public_member")
def gcp_public_member(resources: Dict[str, List[dict]], rule: Any) -> List[Finding]:
    """Flag any IAM binding granted to allUsers / allAuthenticatedUsers.

    These two special members mean "literally anyone on the internet" and
    "anyone with a Google account". A binding to either one on a project is
    almost never intentional and is a fast route to data exposure.
    """
    findings: List[Finding] = []
    public_members = {"allUsers", "allAuthenticatedUsers"}
    for binding in resources.get("iam_binding", []):
        if binding.get("member") in public_members:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    # Granting a public member a primitive role (owner/editor)
                    # is worse than granting a narrow one, so we bump severity
                    # a notch in that case rather than treating all the same.
                    severity=(
                        Severity.CRITICAL
                        if binding.get("is_primitive_role")
                        else rule.severity
                    ),
                    provider="gcp",
                    resource_type="iam_binding",
                    resource_id=f"{binding.get('role')} -> {binding.get('member')}",
                    description=rule.description,
                    remediation=rule.remediation,
                    evidence={
                        "role": binding.get("role"),
                        "member": binding.get("member"),
                        "is_primitive_role": binding.get("is_primitive_role"),
                    },
                    references=rule.references,
                )
            )
    return findings
