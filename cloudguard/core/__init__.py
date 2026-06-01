"""
Core engine pieces: findings model, rule engine, checks, reporting.

Importing checks at package load matters more than it looks: the @check
decorators only run when the module is imported, and that's what fills the
check registry. Pull it in here so that `import cloudguard.core` is enough to
make every named check discoverable, no matter what order the caller imports
things in.
"""

from . import checks  # noqa: F401  (imported for its registration side effects)
from .findings import Finding, Severity, sort_findings, summarize
from .rules import Rule, RuleEngine, load_rules
from .report import write_json, write_markdown, build_json

__all__ = [
    "Finding",
    "Severity",
    "sort_findings",
    "summarize",
    "Rule",
    "RuleEngine",
    "load_rules",
    "write_json",
    "write_markdown",
    "build_json",
]
