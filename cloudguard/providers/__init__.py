"""
Provider package.

We expose a small factory instead of importing the three provider classes up
front. The reason is the lazy-dependency story: each provider imports its cloud
SDK inside __init__, and importing all three eagerly here would drag boto3,
the azure libraries and the google client into every run regardless of which
cloud you're actually scanning. The factory imports exactly the one you asked
for, at the moment you ask for it.
"""

from __future__ import annotations

from .base import CloudProvider


def get_provider(name: str, **kwargs) -> CloudProvider:
    """Construct the provider for `name`, importing only what's needed.

    kwargs are passed straight through to the provider constructor, so the CLI
    can hand each one whatever it needs (profile/region for AWS, subscription
    for Azure, project for GCP) without this factory knowing the specifics.
    """
    name = name.lower()
    if name == "aws":
        from .aws import AWSProvider
        return AWSProvider(**kwargs)
    if name == "azure":
        from .azure import AzureProvider
        return AzureProvider(**kwargs)
    if name == "gcp":
        from .gcp import GCPProvider
        return GCPProvider(**kwargs)
    # Anything else is a user error - list the valid options so it's obvious.
    raise ValueError(f"unknown provider {name!r}. choose one of: aws, azure, gcp")


__all__ = ["CloudProvider", "get_provider"]
