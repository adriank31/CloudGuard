# CloudGuard IAM Report

- **Provider:** aws
- **Account / scope:** 123456789012 (demo)
- **Generated:** 2026-06-01T02:09:38Z
- **Risk score:** 71

## Summary

| Severity | Count |
| --- | --- |
| critical | 1 |
| high | 1 |
| medium | 1 |
| low | 1 |
| info | 0 |
| **Total** | **4** |

## Findings

### [CRITICAL] AWS_IAM_001 - IAM user has administrative access without MFA

- **Resource:** `arn:aws:iam::123456789012:user/root-break-glass`
- **Type:** iam_user

This user can perform any action in the account but logs in with a password alone. A single phished or reused credential here is a full account takeover, which is why it outranks every other IAM finding.

**Evidence**

```json
{
  "user": "root-break-glass",
  "mfa_enabled": false,
  "admin_source": "AdministratorAccess (managed)"
}
```

**Remediation:** Attach and enforce an MFA device for this user immediately, or remove the administrative policy if the access is not actually needed. For day-to-day work prefer assuming a role over standing admin rights on a user.

**References:**
- CIS AWS Foundations: MFA for users with console access

### [HIGH] AWS_IAM_002 - Policy allows all actions on all resources

- **Resource:** `deploy-all`
- **Type:** policy_statement

The policy contains an Allow statement granting Action "*" on Resource "*". That is unrestricted access scoped to whoever the policy is attached to and almost always wider than intended.

**Evidence**

```json
{
  "policy_name": "deploy-all",
  "attached_to": "arn:aws:iam::123456789012:policy/deploy-all",
  "statement": {
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }
}
```

**Remediation:** Replace the wildcard with the specific actions and resource ARNs the workload actually uses. If broad access really is required, scope it with conditions (source IP, MFA present, tag match) rather than leaving it open.

**References:**
- AWS IAM best practices: grant least privilege

### [MEDIUM] AWS_IAM_003 - Access key older than 90 days

- **Resource:** `AKIAOLDKEY00000EXAMPLE`
- **Type:** access_key

Long-lived access keys are a standing liability - the longer one exists the more places it has likely been copied (laptops, CI config, scripts) and the higher the odds it has leaked somewhere.

**Evidence**

```json
{
  "age_days": 820,
  "matched_op": "gt",
  "threshold": 90
}
```

**Remediation:** Rotate the key: create a new one, update whatever uses it, confirm the new key works, then delete the old one. Better still, move the workload to short-lived role credentials so there is no long-lived key to rotate.

**References:**
- CIS AWS Foundations: rotate access keys every 90 days

### [LOW] AWS_IAM_004 - Inactive access key still present

- **Resource:** `AKIASTALEKEY000EXAMPLE`
- **Type:** access_key

The key is disabled but not deleted. A disabled key is one click away from being re-enabled and is one more secret sitting around to be leaked. Stale credentials should be removed, not just parked.

**Evidence**

```json
{
  "status": "Inactive",
  "matched_op": "eq",
  "threshold": "Inactive"
}
```

**Remediation:** If the key is genuinely unused, delete it. Deactivating is fine as a brief safety step before deletion, but it should not be the permanent state.

**References:**
- CIS AWS Foundations: remove unused credentials

