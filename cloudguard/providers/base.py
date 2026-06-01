"""
The contract every cloud provider has to satisfy.

The engine doesn't know or care whether it's looking at AWS, Azure or GCP - it
just wants a dict that maps a resource_type string to a list of plain-dict
resources. Each provider's job is to talk to its cloud's SDK, pull the IAM
state, and flatten it into that shape. All the cloud-specific weirdness stays
behind this boundary.

Keeping the providers this thin (collect data, normalise, return) is what lets
the same rule engine and reporter serve all three clouds.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List


class CloudProvider(ABC):
    # Subclasses set this so error messages and reports can say which cloud
    # they came from without us threading a string around everywhere.
    name: str = "base"

    @abstractmethod
    def collect(self) -> Dict[str, List[dict]]:
        """Gather IAM state and return it as resource_type -> [resources].

        The keys here (iam_user, policy_statement, role_assignment, ...) are the
        same strings the rules reference in their `resource_type` / check logic,
        so the two have to stay in sync. If you add a new resource type to a
        provider, there's no point until a rule actually consumes it.
        """
        raise NotImplementedError
