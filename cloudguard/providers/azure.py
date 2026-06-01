"""
Azure collector.

Azure's RBAC model is different enough from AWS that the normalised resources
look different too. Instead of users-with-policies we have:

  * role_assignment - a principal (user, group or service principal) bound to a
    role at some scope (subscription, resource group, resource). The classic
    over-grant is an Owner or Contributor sitting right at subscription scope.

  * custom_role - a role definition someone in the org authored. These are
    where wildcard actions ("*") tend to creep in.

Auth uses DefaultAzureCredential, which walks the usual chain (env vars, managed
identity, Azure CLI login, etc.). That means in practice you just run `az login`
first and the tool picks up your session - no secrets pasted anywhere.

As with AWS, the SDK imports are lazy so an AWS-only or GCP-only user doesn't
have to install the Azure libraries.
"""

from __future__ import annotations

from typing import Dict, List

from .base import CloudProvider


# Built-in Azure roles that hand out broad power. Held at subscription scope,
# any of these is worth a second look. The GUIDs are stable across all tenants,
# but matching on the friendly name read from the role definition is plenty here.
_PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator"}


def _scope_level(scope: str) -> str:
    """Classify an Azure scope string into a coarse level.

    Scopes look like /subscriptions/<id>[/resourceGroups/<rg>[/providers/...]].
    The deeper the path, the narrower the blast radius - a role at subscription
    scope is far scarier than the same role on one resource, so a rule wants to
    distinguish them.
    """
    # Count the segments to figure out how deep the scope goes.
    if "/providers/" in scope or scope.count("/") > 4:
        return "resource"
    if "/resourceGroups/" in scope or scope.count("/") > 2:
        return "resource_group"
    return "subscription"


class AzureProvider(CloudProvider):
    name = "azure"

    def __init__(self, subscription_id: str):
        # Lazy imports - see the module docstring.
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.authorization import AuthorizationManagementClient

        # Subscription id is required: Azure RBAC is always scoped to a sub (or
        # below), so there's no sensible "scan everything" without one.
        self.subscription_id = subscription_id
        credential = DefaultAzureCredential()
        self.client = AuthorizationManagementClient(credential, subscription_id)

    def collect(self) -> Dict[str, List[dict]]:
        # Pull role definitions first and key them by id, because each role
        # assignment only references its role by id and we want the human name.
        definitions = self._collect_role_definitions()
        return {
            "role_assignment": self._collect_role_assignments(definitions),
            "custom_role": [d for d in definitions.values() if d["is_custom"]],
        }

    def _collect_role_definitions(self) -> Dict[str, dict]:
        scope = f"/subscriptions/{self.subscription_id}"
        definitions: Dict[str, dict] = {}
        for role in self.client.role_definitions.list(scope):
            # role_type is "BuiltInRole" or "CustomRole"; we only get to fix the
            # custom ones, but we keep both so assignments can be named.
            is_custom = role.role_type == "CustomRole"
            # A custom role with "*" in its allowed actions can do anything in
            # its scope - effectively a home-grown admin role. Flag the wildcard.
            actions = []
            for perm in role.permissions or []:
                actions.extend(perm.actions or [])
            definitions[role.id] = {
                "id": role.id,
                "name": role.role_name,
                "is_custom": is_custom,
                "has_wildcard_action": "*" in actions,
                "actions": actions,
            }
        return definitions

    def _collect_role_assignments(self, definitions: Dict[str, dict]) -> List[dict]:
        scope = f"/subscriptions/{self.subscription_id}"
        out: List[dict] = []
        for assignment in self.client.role_assignments.list_for_scope(scope):
            role_def = definitions.get(assignment.role_definition_id, {})
            role_name = role_def.get("name", "<unknown role>")
            level = _scope_level(assignment.scope or scope)
            out.append(
                {
                    "id": assignment.name,                       # the assignment guid
                    "principal_id": assignment.principal_id,
                    "principal_type": assignment.principal_type, # User/Group/ServicePrincipal
                    "role_name": role_name,
                    "scope": assignment.scope,
                    "scope_level": level,
                    # Pre-compute the "is this a dangerous combo" flag so the YAML
                    # rule can be a one-field match rather than a multi-condition.
                    "is_privileged_at_subscription": (
                        role_name in _PRIVILEGED_ROLES and level == "subscription"
                    ),
                }
            )
        return out
