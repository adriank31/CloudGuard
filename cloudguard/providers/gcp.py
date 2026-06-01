"""
GCP collector.

GCP's IAM is a flat policy on a resource (here, a project): a list of bindings,
each pairing a role with a set of members. We explode those bindings out so
there's one normalised resource per role/member pair - that way a rule can flag
a single bad grant instead of a whole binding.

Two things we specifically look out for, surfaced as flags on each binding:

  * Primitive roles (roles/owner, roles/editor, roles/viewer). These are the
    legacy broad roles Google itself recommends moving away from in favour of
    predefined or custom roles.

  * Public members (allUsers, allAuthenticatedUsers). A grant to either is open
    to the internet and almost always a mistake at the project level.

Auth goes through Application Default Credentials, so `gcloud auth
application-default login` (or a service account key via the usual env var) is
all that's needed. SDK import is lazy like the other providers.
"""

from __future__ import annotations

from typing import Dict, List

from .base import CloudProvider


# The three legacy "primitive" roles. Membership in this set is what flips the
# is_primitive_role flag, which the public-member check uses to decide whether a
# public grant is merely bad or downright critical.
_PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}

# The two magic members that mean "everyone". Kept as a module constant so the
# provider and the check in checks.py agree on the exact strings.
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class GCPProvider(CloudProvider):
    name = "gcp"

    def __init__(self, project_id: str):
        # Lazy import of the Google API client. We use the generic discovery
        # client rather than a hand-specific library because getIamPolicy is a
        # single, stable call and discovery keeps the dependency surface small.
        from googleapiclient import discovery

        self.project_id = project_id
        # cache_discovery=False silences a noisy warning on newer setups and
        # avoids writing a cache file into the user's home dir during a scan.
        self.crm = discovery.build("cloudresourcemanager", "v1", cache_discovery=False)

    def collect(self) -> Dict[str, List[dict]]:
        return {"iam_binding": self._collect_bindings()}

    def _collect_bindings(self) -> List[dict]:
        # getIamPolicy returns the whole project policy in one call - no
        # pagination to worry about, unlike the AWS list APIs.
        policy = (
            self.crm.projects()
            .getIamPolicy(resource=self.project_id, body={})
            .execute()
        )

        out: List[dict] = []
        for binding in policy.get("bindings", []):
            role = binding["role"]
            is_primitive = role in _PRIMITIVE_ROLES
            # A binding lists many members under one role. We flatten to one
            # record per member so each grant can be flagged (and remediated)
            # on its own rather than as an all-or-nothing block.
            for member in binding.get("members", []):
                out.append(
                    {
                        "id": f"{role}::{member}",
                        "role": role,
                        "member": member,
                        # member strings are prefixed by type: user:, group:,
                        # serviceAccount:, etc. Split that off so a rule can
                        # match on member type if it wants to.
                        "member_type": member.split(":", 1)[0] if ":" in member else member,
                        "is_primitive_role": is_primitive,
                        "is_public": member in _PUBLIC_MEMBERS,
                    }
                )
        return out
