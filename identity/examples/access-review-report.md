# Identity Access Review

Generated: `2026-07-31T08:00:50.322968+00:00`
Stale account threshold: `45` days

## Summary

| Metric | Count |
| --- | ---: |
| Users | 5 |
| Enabled Users | 4 |
| Privileged Assignments | 2 |
| Group Memberships | 3 |
| Critical Findings | 1 |
| High Findings | 4 |
| Medium Findings | 3 |
| Low Findings | 0 |

## Findings

| Severity | Category | Principal | Summary | Recommendation |
| --- | --- | --- | --- | --- |
| CRITICAL | mfa gap | `shared.scanner@example.com` | Enabled account is not registered for MFA. | Require MFA registration or move the account behind an approved conditional access exception. |
| HIGH | mfa gap | `casey.contractor@example.com` | Enabled account is not registered for MFA. | Require MFA registration or move the account behind an approved conditional access exception. |
| HIGH | privileged role | `alex.admin@example.com` | Account has high-risk role assignment: Global Administrator. | Confirm the role is still required, eligible instead of permanent when possible, and covered by MFA. |
| HIGH | privileged role | `shared.scanner@example.com` | Account has high-risk role assignment: Exchange Administrator. | Confirm the role is still required, eligible instead of permanent when possible, and covered by MFA. |
| HIGH | stale account | `shared.scanner@example.com` | Enabled account has no readable last sign-in value. | Confirm whether this account is still required, then disable or document an approved exception. |
| MEDIUM | guest access | `casey.contractor@example.com` | Guest account has 0 role assignment(s) and 1 group membership(s). | Review sponsor, business need, group membership, and expiration date. |
| MEDIUM | stale account | `casey.contractor@example.com` | Enabled account has not signed in for 59 days. | Review ownership and disable the account when it is no longer needed. |
| MEDIUM | stale account | `retired.user@example.com` | Enabled account has not signed in for 137 days. | Review ownership and disable the account when it is no longer needed. |
