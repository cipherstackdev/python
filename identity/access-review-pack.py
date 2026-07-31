#!/usr/bin/env python3
"""Build an access review report from exported identity CSV files."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_STALE_DAYS = 45
HIGH_RISK_ROLES = {
    "global administrator",
    "privileged role administrator",
    "exchange administrator",
    "sharepoint administrator",
    "user administrator",
    "security administrator",
    "intune administrator",
    "authentication administrator",
}


@dataclass(frozen=True)
class UserRecord:
    user_principal_name: str
    display_name: str
    department: str
    account_enabled: bool
    mfa_registered: bool
    user_type: str
    last_sign_in: dt.datetime | None


@dataclass(frozen=True)
class RoleAssignment:
    user_principal_name: str
    role_name: str
    assignment_type: str


@dataclass(frozen=True)
class GroupMembership:
    user_principal_name: str
    group_name: str
    group_type: str


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    principal: str
    summary: str
    recommendation: str


@dataclass(frozen=True)
class AccessReviewReport:
    generated_at: str
    stale_days: int
    summary: dict[str, int]
    findings: list[Finding]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [{key.strip(): (value or "").strip() for key, value in row.items()} for row in csv.DictReader(handle)]


def require_columns(rows: list[dict[str, str]], path: Path, required: set[str]) -> None:
    if not rows:
        raise ValueError(f"{path} has no rows.")
    missing = required.difference(rows[0].keys())
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")


def bool_value(value: str) -> bool:
    return value.strip().lower() in {"true", "yes", "y", "1", "enabled"}


def parse_datetime(value: str) -> dt.datetime | None:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = dt.datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def load_users(path: Path) -> list[UserRecord]:
    rows = read_csv(path)
    require_columns(
        rows,
        path,
        {
            "user_principal_name",
            "display_name",
            "department",
            "account_enabled",
            "mfa_registered",
            "user_type",
            "last_sign_in",
        },
    )
    return [
        UserRecord(
            user_principal_name=row["user_principal_name"].lower(),
            display_name=row["display_name"],
            department=row["department"],
            account_enabled=bool_value(row["account_enabled"]),
            mfa_registered=bool_value(row["mfa_registered"]),
            user_type=row["user_type"],
            last_sign_in=parse_datetime(row["last_sign_in"]),
        )
        for row in rows
    ]


def load_roles(path: Path | None) -> list[RoleAssignment]:
    if path is None:
        return []
    rows = read_csv(path)
    require_columns(rows, path, {"user_principal_name", "role_name", "assignment_type"})
    return [
        RoleAssignment(
            user_principal_name=row["user_principal_name"].lower(),
            role_name=row["role_name"],
            assignment_type=row["assignment_type"],
        )
        for row in rows
    ]


def load_groups(path: Path | None) -> list[GroupMembership]:
    if path is None:
        return []
    rows = read_csv(path)
    require_columns(rows, path, {"user_principal_name", "group_name", "group_type"})
    return [
        GroupMembership(
            user_principal_name=row["user_principal_name"].lower(),
            group_name=row["group_name"],
            group_type=row["group_type"],
        )
        for row in rows
    ]


def index_by_user(items: Iterable[RoleAssignment | GroupMembership]) -> dict[str, list[RoleAssignment | GroupMembership]]:
    index: dict[str, list[RoleAssignment | GroupMembership]] = {}
    for item in items:
        index.setdefault(item.user_principal_name, []).append(item)
    return index


def add_finding(findings: list[Finding], severity: str, category: str, principal: str, summary: str, recommendation: str) -> None:
    findings.append(Finding(severity, category, principal, summary, recommendation))


def build_report(
    users: list[UserRecord],
    roles: list[RoleAssignment],
    groups: list[GroupMembership],
    stale_days: int,
) -> AccessReviewReport:
    now = dt.datetime.now(dt.timezone.utc)
    role_index = index_by_user(roles)
    group_index = index_by_user(groups)
    findings: list[Finding] = []

    for user in users:
        user_roles = role_index.get(user.user_principal_name, [])
        user_groups = group_index.get(user.user_principal_name, [])
        high_risk_roles = [role for role in user_roles if role.role_name.lower() in HIGH_RISK_ROLES]

        if user.account_enabled and user.last_sign_in is None:
            add_finding(
                findings,
                "high",
                "stale account",
                user.user_principal_name,
                "Enabled account has no readable last sign-in value.",
                "Confirm whether this account is still required, then disable or document an approved exception.",
            )
        elif user.account_enabled and user.last_sign_in:
            inactive_days = (now - user.last_sign_in).days
            if inactive_days >= stale_days:
                add_finding(
                    findings,
                    "medium",
                    "stale account",
                    user.user_principal_name,
                    f"Enabled account has not signed in for {inactive_days} days.",
                    "Review ownership and disable the account when it is no longer needed.",
                )

        if user.account_enabled and not user.mfa_registered:
            severity = "critical" if high_risk_roles else "high"
            add_finding(
                findings,
                severity,
                "mfa gap",
                user.user_principal_name,
                "Enabled account is not registered for MFA.",
                "Require MFA registration or move the account behind an approved conditional access exception.",
            )

        if high_risk_roles:
            role_names = ", ".join(sorted(role.role_name for role in high_risk_roles))
            add_finding(
                findings,
                "high",
                "privileged role",
                user.user_principal_name,
                f"Account has high-risk role assignment: {role_names}.",
                "Confirm the role is still required, eligible instead of permanent when possible, and covered by MFA.",
            )

        if user.user_type.lower() == "guest" and (user_roles or user_groups):
            add_finding(
                findings,
                "medium",
                "guest access",
                user.user_principal_name,
                f"Guest account has {len(user_roles)} role assignment(s) and {len(user_groups)} group membership(s).",
                "Review sponsor, business need, group membership, and expiration date.",
            )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (severity_order.get(item.severity, 9), item.category, item.principal))
    summary = {
        "users": len(users),
        "enabled_users": sum(1 for user in users if user.account_enabled),
        "privileged_assignments": len(roles),
        "group_memberships": len(groups),
        "critical_findings": sum(1 for finding in findings if finding.severity == "critical"),
        "high_findings": sum(1 for finding in findings if finding.severity == "high"),
        "medium_findings": sum(1 for finding in findings if finding.severity == "medium"),
        "low_findings": sum(1 for finding in findings if finding.severity == "low"),
    }
    return AccessReviewReport(
        generated_at=now.isoformat(),
        stale_days=stale_days,
        summary=summary,
        findings=findings,
    )


def markdown(report: AccessReviewReport) -> str:
    lines = [
        "# Identity Access Review",
        "",
        f"Generated: `{report.generated_at}`",
        f"Stale account threshold: `{report.stale_days}` days",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    for key, value in report.summary.items():
        lines.append(f"| {key.replace('_', ' ').title()} | {value} |")

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings generated from the provided CSV files.")
    else:
        lines.extend(["| Severity | Category | Principal | Summary | Recommendation |", "| --- | --- | --- | --- | --- |"])
        for finding in report.findings:
            lines.append(
                f"| {finding.severity.upper()} | {finding.category} | `{finding.principal}` | "
                f"{finding.summary} | {finding.recommendation} |"
            )
    lines.append("")
    return "\n".join(lines)


def write_output(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an access review report from exported identity CSV files.")
    parser.add_argument("--users", type=Path, required=True, help="CSV with user inventory")
    parser.add_argument("--roles", type=Path, help="CSV with privileged role assignments")
    parser.add_argument("--groups", type=Path, help="CSV with group memberships")
    parser.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS, help="Days without sign-in before flagging stale accounts")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown")
    parser.add_argument("--output", type=Path, help="Optional output file")
    args = parser.parse_args()

    try:
        report = build_report(load_users(args.users), load_roles(args.roles), load_groups(args.groups), args.stale_days)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        content = json.dumps(asdict(report), indent=2)
    else:
        content = markdown(report)

    if args.output:
        write_output(args.output, content)
        print(f"Wrote report to {args.output}")
    else:
        print(content)

    return 1 if report.summary["critical_findings"] or report.summary["high_findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
