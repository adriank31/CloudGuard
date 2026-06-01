# CloudGuard

A command-line scanner that pulls IAM state out of AWS, Azure or GCP and flags
the misconfigurations that show up over and over in real accounts: admins
without MFA, policies that allow `*` on `*`, access keys that have been sitting
around for two years, public IAM bindings, primitive roles where a scoped one
would do.

It's deliberately small. There are big, excellent tools in this space
(ScoutSuite, Prowler, CloudSploit) and CloudGuard isn't trying to replace them.
I built it because I wanted one tool with a single normalised finding model
across all three clouds, a ruleset I could read and edit in plain YAML, and
output that drops straight into a pull request or a ticket without reformatting.

## What it checks

The bundled ruleset is small on purpose - these are the findings I reach for
first when I look at an account cold.

**AWS**
- `AWS_IAM_001` IAM user with admin access and no MFA *(critical)*
- `AWS_IAM_002` policy statement allowing all actions on all resources *(high)*
- `AWS_IAM_003` access key older than 90 days *(medium)*
- `AWS_IAM_004` inactive access key that was never deleted *(low)*

**Azure**
- `AZURE_IAM_001` Owner/Contributor/User Access Administrator at subscription scope *(high)*
- `AZURE_IAM_002` custom role granting wildcard actions *(high)*

**GCP**
- `GCP_IAM_001` binding granting a role to `allUsers` / `allAuthenticatedUsers` *(high, escalates to critical on a primitive role)*
- `GCP_IAM_002` primitive role (`roles/owner`, `roles/editor`, `roles/viewer`) in use *(medium)*

Adding your own is mostly an exercise in editing YAML - see [Writing rules](#writing-rules).

## Install

```bash
git clone https://github.com/adriank31/cloudguard.git
cd cloudguard

# Install with only the cloud you need. The SDKs are heavy, so they're optional
# extras rather than hard dependencies.
pip install -e ".[aws]"      # boto3 only
pip install -e ".[azure]"    # azure libraries only
pip install -e ".[gcp]"      # google client only
pip install -e ".[all]"      # everything + pytest, for working on the tool
```

After install you get a `cloudguard` command. If you'd rather not install, every
example below also works with `python -m cloudguard.cli ...`.

## Try it without a cloud account

There's a saved AWS snapshot under `examples/` so you can see the whole pipeline
run with no credentials and no network:

```bash
cloudguard --provider aws \
  --from-file examples/demo_aws_resources.json \
  --account "123456789012 (demo)"
```

That prints a Markdown report to your terminal. The committed
`examples/sample_report.md` is exactly what that command produces.

## Real usage

CloudGuard reads credentials the same way the official SDKs and CLIs do, so
there are no secrets to paste in - you authenticate however you normally would,
then point the tool at the account.

**AWS** (uses your `~/.aws` profiles):

```bash
cloudguard --provider aws --profile prod --format markdown --output prod-iam.md
```

**Azure** (run `az login` first):

```bash
cloudguard --provider azure --subscription 00000000-0000-0000-0000-000000000000
```

**GCP** (run `gcloud auth application-default login` first):

```bash
cloudguard --provider gcp --project my-project-id --format json
```

### Useful flags

| Flag | What it does |
| --- | --- |
| `--format {markdown,json}` | Report format. Markdown is the default; JSON is for piping into other tools. |
| `--output PATH` | Write to a file instead of stdout. |
| `--rules PATH` | Use a different rules file or directory instead of the bundled one. |
| `--from-file PATH` | Read a saved resource snapshot instead of calling the cloud. |
| `--account LABEL` | Label shown in the report header. |
| `--fail-on SEVERITY` | Exit non-zero if anything at or above this severity is found. |

### Using it as a CI gate

`--fail-on` makes the process exit `1` when there's a finding at or above the
level you pick, so a pipeline step can block a merge on it:

```bash
# Fail the build if there's anything high or worse.
cloudguard --provider aws --profile ci --fail-on high
```

Exit codes: `0` clean (or only findings below the threshold), `1` the gate
tripped, `2` something was wrong with the invocation (bad flags, missing
credentials, unreadable rules).

## Writing rules

Rules live in `cloudguard/rules/<provider>.yaml`. There are two kinds.

**Declarative rules** compare one field on a resource to a value. No code:

```yaml
- id: AWS_IAM_003
  title: Access key older than 90 days
  severity: medium
  provider: aws
  resource_type: access_key      # which list of resources to walk
  description: >
    Long-lived keys are a standing liability...
  remediation: >
    Rotate the key, or move to short-lived role credentials...
  match:
    field: age_days              # field on the resource
    op: gt                       # eq, ne, gt, gte, lt, lte, in, contains, exists, regex
    value: 90
```

**Check rules** name a Python function for logic a single comparison can't
express - cross-referencing two resources, parsing a policy document:

```yaml
- id: AWS_IAM_001
  title: IAM user has administrative access without MFA
  severity: critical
  provider: aws
  check: aws_admin_without_mfa   # a function registered in core/checks.py
  description: >
    ...
  remediation: >
    ...
```

To add a check, write a function in `cloudguard/core/checks.py`, decorate it
with `@check("your_name")`, return a list of `Finding` objects, and reference
the name from a rule. The existing checks are short and are the best template.

## How it's put together

The one design decision everything else follows from is the **normalisation
boundary**. Each provider's only job is to talk to its cloud's SDK and flatten
what it finds into plain dictionaries keyed by resource type:

```
providers/aws.py  ─┐
providers/azure.py ─┼─►  { "iam_user": [...], "access_key": [...], ... }  ─►  RuleEngine  ─►  Findings  ─►  report
providers/gcp.py  ─┘            (normalised resources)
```

The rule engine and the reporters never know or care which cloud the data came
from. That's what lets one ruleset format and one report format serve all
three, and it's why the whole engine is testable offline - the tests just hand
it the same dictionaries a provider would produce (see `tests/test_rules.py`).

```
cloudguard/
├── cli.py              # argument parsing and orchestration
├── core/
│   ├── findings.py     # Finding + Severity model, risk scoring
│   ├── rules.py        # YAML loading + the evaluation engine
│   ├── checks.py       # named check functions + their registry
│   └── report.py       # JSON and Markdown writers
├── providers/
│   ├── base.py         # the collect() contract
│   ├── aws.py          # boto3
│   ├── azure.py        # azure-identity + azure-mgmt-authorization
│   └── gcp.py          # google-api-python-client
└── rules/
    ├── aws.yaml
    ├── azure.yaml
    └── gcp.yaml
```

## Tests

```bash
pip install pytest
pytest
```

The suite runs entirely offline. It loads the real bundled ruleset and runs it
against hand-built resource fixtures, so it exercises both the declarative
matcher and the named checks without ever touching a cloud.

## Limitations / things I'd do next

Being honest about where this stops:

- **Read scope.** It only reads IAM. It does not look at network config, storage
  bucket ACLs, logging, encryption settings, etc. The architecture would take
  new resource types fine, I just haven't written those collectors.
- **Single account / subscription / project per run.** No org-wide or
  multi-account sweep yet. You'd wrap it in a loop for now.
- **Permissions.** The scan needs read access to IAM (e.g. an AWS role with
  `iam:List*` / `iam:Get*`). It never writes anything, but it will error out if
  it can't read what a rule needs.
- **The ruleset is a starting point, not a benchmark.** It's the handful of
  checks I find most useful, not a full CIS implementation. Treat the findings
  as leads to confirm, not gospel.
- **Azure/GCP collectors are thinner than the AWS one.** AWS got the most
  attention because it's where I spend the most time; the other two cover the
  headline misconfigurations but less of the long tail.

## License

MIT. See [LICENSE](LICENSE).
