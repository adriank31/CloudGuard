"""
Command-line interface.

This is the glue: parse the flags, collect resources (either live from a cloud
or from a saved JSON file), run them through the engine, and print a report.

The --from-file path deserves a word. It loads the normalised resources from a
JSON file instead of calling a cloud API. That's there for three reasons:

  1. You can demo the whole pipeline without any cloud credentials.
  2. CI can run the engine against fixtures with no network at all.
  3. You can snapshot a real account's resources once and then iterate on rules
     against that snapshot offline.

The --fail-on flag makes the tool usable as a CI gate: point it at, say, "high"
and the process exits non-zero the moment a high-or-worse finding shows up, so
a pipeline step can block on it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import RuleEngine, Severity, load_rules, write_json, write_markdown


# Where the bundled rules live, relative to this file. Resolving it off __file__
# means the rules ship and load correctly whether the tool is run from a clone,
# an installed wheel, or a zip - we never assume a working directory.
_DEFAULT_RULES_DIR = Path(__file__).parent / "rules"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="Scan cloud IAM for common misconfigurations.",
    )
    parser.add_argument(
        "--version", action="version", version=f"cloudguard {__version__}"
    )

    parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp"],
        required=True,
        help="which cloud to scan",
    )

    # Provider-specific knobs. We don't enforce which combos make sense here -
    # the provider constructor does that - we just accept them all and pass the
    # relevant ones through.
    parser.add_argument("--profile", help="AWS named profile (aws only)")
    parser.add_argument("--region", help="AWS region (aws only; IAM is global so optional)")
    parser.add_argument("--subscription", help="Azure subscription id (azure only)")
    parser.add_argument("--project", help="GCP project id (gcp only)")

    parser.add_argument(
        "--rules",
        type=Path,
        default=_DEFAULT_RULES_DIR,
        help="path to a rules file or directory (defaults to the bundled ruleset)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="output format (default: markdown)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the report here instead of stdout",
    )
    parser.add_argument(
        "--from-file",
        type=Path,
        help="load normalised resources from a JSON file instead of calling the cloud",
    )
    parser.add_argument(
        "--account",
        default="",
        help="label for the scanned account/subscription/project (shown in the report)",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit non-zero if any finding is at or above this severity (for CI gating)",
    )
    return parser


def _collect_resources(args) -> dict:
    """Get the resource bag either from a file or from a live cloud call."""
    # File path wins if given - it's the offline/demo/CI route and shouldn't
    # require any provider credentials to be present.
    if args.from_file:
        return json.loads(Path(args.from_file).read_text())

    # Otherwise go live. Import the factory lazily so --from-file runs never
    # even touch the provider package (and thus never import a cloud SDK).
    from .providers import get_provider

    # Hand each provider only the kwargs it actually understands. Passing AWS's
    # profile to the GCP provider would just be confusing, so we branch.
    if args.provider == "aws":
        provider = get_provider("aws", profile=args.profile, region=args.region)
    elif args.provider == "azure":
        if not args.subscription:
            _die("--subscription is required for an Azure scan")
        provider = get_provider("azure", subscription_id=args.subscription)
    else:  # gcp
        if not args.project:
            _die("--project is required for a GCP scan")
        provider = get_provider("gcp", project_id=args.project)

    return provider.collect()


def _die(message: str) -> None:
    """Print an error to stderr and bail with a non-zero status."""
    # stderr (not stdout) so it doesn't end up mixed into a report someone is
    # piping to a file. Exit code 2 mirrors argparse's own usage-error code.
    print(f"cloudguard: error: {message}", file=sys.stderr)
    sys.exit(2)


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Load the ruleset, narrowed to the chosen provider so we don't waste time
    # evaluating Azure rules during an AWS scan.
    try:
        rules = load_rules(args.rules, provider=args.provider)
    except (ValueError, OSError) as exc:
        _die(f"could not load rules: {exc}")

    if not rules:
        # A scan with zero applicable rules would silently "pass" everything,
        # which is misleading. Warn loudly but keep going - maybe that's intended.
        print(
            f"cloudguard: warning: no rules matched provider {args.provider!r}",
            file=sys.stderr,
        )

    # Pull the resources (live or from file), then run the engine over them.
    try:
        resources = _collect_resources(args)
    except FileNotFoundError as exc:
        _die(f"resource file not found: {exc}")
    except ImportError as exc:
        # This is what you hit if the relevant cloud SDK isn't installed. Point
        # the user at the fix rather than dumping a raw traceback on them.
        _die(f"missing SDK for {args.provider} scan ({exc}); install the matching extra")

    engine = RuleEngine(rules)
    findings = engine.run(resources)

    # Render. The account label defaults to the provider name if the user didn't
    # give one, so the report header is never blank.
    account = args.account or f"<{args.provider} account>"
    if args.format == "json":
        report = write_json(findings, args.provider, account)
    else:
        report = write_markdown(findings, args.provider, account)

    # Write out. A trailing newline keeps shells and editors happy when the
    # report lands in a file.
    if args.output:
        args.output.write_text(report + "\n")
        print(f"wrote {len(findings)} findings to {args.output}", file=sys.stderr)
    else:
        print(report)

    # CI gating. If --fail-on was set, compare the worst finding against the
    # threshold and exit 1 if we're at or over it. Exit 0 otherwise.
    if args.fail_on:
        threshold = Severity.from_string(args.fail_on)
        # rank is "lower == worse", so a finding trips the gate when its rank is
        # less than or equal to the threshold's rank.
        tripped = any(f.severity.rank <= threshold.rank for f in findings)
        if tripped:
            print(
                f"cloudguard: failing - found findings at or above {args.fail_on}",
                file=sys.stderr,
            )
            return 1

    return 0


# Standard entry guard so `python -m cloudguard.cli` works alongside the
# installed `cloudguard` console script.
if __name__ == "__main__":
    sys.exit(main())
