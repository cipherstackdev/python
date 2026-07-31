# Identity Admin Utilities

Public-safe Python tools for identity inventory review, access cleanup, and audit preparation.

## Scripts

| Script | Purpose |
| --- | --- |
| `access-review-pack.py` | Builds a Markdown or JSON access review report from user, role, and group CSV exports. |

## Setup

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CSV Inputs

The tool expects admin exports that have been sanitized before publication or sharing.

### Users CSV

Required columns:

```csv
user_principal_name,display_name,department,account_enabled,mfa_registered,user_type,last_sign_in
```

### Roles CSV

Required columns:

```csv
user_principal_name,role_name,assignment_type
```

### Groups CSV

Required columns:

```csv
user_principal_name,group_name,group_type
```

## Usage

Markdown report:

```bash
python identity/access-review-pack.py \
  --users identity/examples/users.csv \
  --roles identity/examples/roles.csv \
  --groups identity/examples/groups.csv \
  --output identity-access-review.md
```

JSON report:

```bash
python identity/access-review-pack.py \
  --users identity/examples/users.csv \
  --roles identity/examples/roles.csv \
  --groups identity/examples/groups.csv \
  --json
```

Custom stale account threshold:

```bash
python identity/access-review-pack.py \
  --users identity/examples/users.csv \
  --roles identity/examples/roles.csv \
  --groups identity/examples/groups.csv \
  --stale-days 60
```

## What It Flags

- Enabled accounts with no readable last sign-in.
- Enabled accounts that have not signed in within the stale threshold.
- Enabled accounts missing MFA registration.
- High-risk administrative role assignments.
- Guest accounts with group or role access.

## Public Safety Notes

- Do not commit production identity exports.
- Replace names, domains, departments, and group names before sharing reports publicly.
- Treat access review output as sensitive unless it has been explicitly approved for release.
- This tool reviews CSV data; it does not connect to Microsoft Graph, Google Workspace, or an identity provider directly.
