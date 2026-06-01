"""
AWS collector.

Walks IAM with boto3 and flattens what it finds into the normalised resource
dicts the engine expects. The interesting bits:

  * IAM list calls paginate, and the page size is small, so we lean on boto3's
    built-in paginators rather than hand-rolling NextToken loops.

  * Working out whether a user is "admin" means looking at both their managed
    policies (is AdministratorAccess attached?) and their inline ones (does any
    statement grant *:*?). We do that once per user and stash the answer on the
    user dict so the rule check can stay simple.

  * boto3 hands back timezone-aware datetimes for key creation; we convert those
    to an age-in-days integer here so the rules can just compare numbers.

boto3 is imported lazily inside __init__ so that someone who only wants to scan
GCP doesn't need AWS credentials or even boto3 installed to run the tool.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from .base import CloudProvider


# The AWS-managed policy ARN that grants full admin. Matching on the ARN is more
# reliable than matching on the name, since names can collide with customer-made
# policies but this ARN is global and fixed.
_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _age_in_days(moment: datetime) -> int:
    """How many whole days ago was `moment`?

    boto3 returns aware datetimes (UTC). We compare against an aware 'now' so
    Python doesn't throw the naive-vs-aware subtraction error, then floor to
    whole days because nobody writes a rule like "key older than 90.4 days".
    """
    now = datetime.now(timezone.utc)
    return (now - moment).days


class AWSProvider(CloudProvider):
    name = "aws"

    def __init__(self, profile: str = None, region: str = None):
        # Import here, not at module top, so the dependency is optional per the
        # note above. boto3 is the only hard requirement for an AWS scan.
        import boto3  # noqa: PLC0415 (intentional lazy import)

        # A named profile lets people scan whichever account their ~/.aws/config
        # points at; region rarely matters for IAM (it's global) but we accept
        # it so the session construction is uniform.
        session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = session.client("iam")

    def collect(self) -> Dict[str, List[dict]]:
        users = self._collect_users()
        # Policy statements come partly from the same user walk (inline) and
        # partly from attached managed policies; gather both into one list.
        statements = self._collect_policy_statements()
        return {
            "iam_user": users,
            "access_key": self._collect_access_keys(users),
            "policy_statement": statements,
        }

    # -- users --------------------------------------------------------------

    def _collect_users(self) -> List[dict]:
        out: List[dict] = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                name = user["UserName"]
                # Two extra calls per user. On large accounts this is the slow
                # part of the scan, but there's no bulk API that returns MFA +
                # policy state in one shot, so per-user calls it is.
                mfa_enabled = self._user_has_mfa(name)
                has_admin, admin_source = self._user_is_admin(name)
                out.append(
                    {
                        "name": name,
                        "arn": user["Arn"],
                        "id": user["UserId"],
                        "created": user["CreateDate"].isoformat(),
                        "mfa_enabled": mfa_enabled,
                        "has_admin": has_admin,
                        # Record *why* we called them admin - the report shows
                        # this and it saves the reader from re-investigating.
                        "admin_source": admin_source,
                    }
                )
        return out

    def _user_has_mfa(self, username: str) -> bool:
        # An empty MFADevices list means password-only. We don't care which kind
        # of device (virtual vs hardware), only that at least one exists.
        devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
        return len(devices) > 0

    def _user_is_admin(self, username: str) -> (bool, str):
        # First the cheap check: is the managed AdministratorAccess policy
        # attached directly? This catches the overwhelmingly common case.
        attached = self.iam.list_attached_user_policies(UserName=username)
        for policy in attached["AttachedPolicies"]:
            if policy["PolicyArn"] == _ADMIN_POLICY_ARN:
                return True, "AdministratorAccess (managed)"

        # Then the slower check: scan inline policies for a *:* allow. People
        # love pasting these in, and they don't show up in the managed list.
        inline_names = self.iam.list_user_policies(UserName=username)["PolicyNames"]
        for policy_name in inline_names:
            doc = self.iam.get_user_policy(UserName=username, PolicyName=policy_name)
            if self._document_grants_full_admin(doc["PolicyDocument"]):
                return True, f"inline policy {policy_name} (*:* allow)"

        return False, ""

    @staticmethod
    def _document_grants_full_admin(document: Dict[str, Any]) -> bool:
        # A policy document's Statement can be a single object or a list; handle
        # both. We're looking for an Allow with Action and Resource both "*".
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            action = stmt.get("Action")
            resource = stmt.get("Resource")
            action_wild = action == "*" or (isinstance(action, list) and "*" in action)
            resource_wild = resource == "*" or (isinstance(resource, list) and "*" in resource)
            if action_wild and resource_wild:
                return True
        return False

    # -- access keys --------------------------------------------------------

    def _collect_access_keys(self, users: List[dict]) -> List[dict]:
        out: List[dict] = []
        for user in users:
            name = user["name"]
            keys = self.iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
            for key in keys:
                out.append(
                    {
                        "id": key["AccessKeyId"],
                        "user": name,
                        "status": key["Status"],          # Active | Inactive
                        "created": key["CreateDate"].isoformat(),
                        # Pre-computed so the age rule is a plain numeric compare.
                        "age_days": _age_in_days(key["CreateDate"]),
                    }
                )
        return out

    # -- policy statements --------------------------------------------------

    def _collect_policy_statements(self) -> List[dict]:
        """Flatten every customer-managed policy into individual statements.

        We only walk Scope='Local' (customer-managed) policies - the hundreds of
        AWS-managed ones aren't ours to fix and would drown the report. Each
        statement becomes its own resource so a wildcard rule can point at the
        exact statement rather than the whole policy.
        """
        out: List[dict] = []
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=False):
            for policy in page["Policies"]:
                # We need the actual document, which lives on a specific version.
                version = self.iam.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=policy["DefaultVersionId"],
                )
                document = version["PolicyVersion"]["Document"]
                statements = document.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    out.append(
                        {
                            "policy_name": policy["PolicyName"],
                            "attached_to": policy["Arn"],
                            "effect": stmt.get("Effect"),
                            # The check functions parse Action/Resource off this.
                            "document": stmt,
                        }
                    )
        return out
