#!/usr/bin/env python3
"""Audit a subnet/VLAN inventory CSV for common network hygiene issues."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


REQUIRED_COLUMNS = {
    "site",
    "vlan_id",
    "name",
    "cidr",
    "gateway",
    "dhcp_start",
    "dhcp_end",
    "owner",
    "purpose",
}


@dataclass(frozen=True)
class SubnetRecord:
    site: str
    vlan_id: str
    name: str
    cidr: str
    gateway: str
    dhcp_start: str
    dhcp_end: str
    owner: str
    purpose: str


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    item: str
    summary: str
    recommendation: str


@dataclass(frozen=True)
class AuditReport:
    source: str
    subnet_count: int
    summary: dict[str, int]
    findings: list[Finding]


def read_inventory(path: Path) -> list[SubnetRecord]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [{key.strip(): (value or "").strip() for key, value in row.items()} for row in csv.DictReader(handle)]
    if not rows:
        raise ValueError(f"{path} has no rows.")
    missing = REQUIRED_COLUMNS.difference(rows[0].keys())
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")
    return [SubnetRecord(**{column: row[column] for column in REQUIRED_COLUMNS}) for row in rows]


def parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def parse_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def add_finding(findings: list[Finding], severity: str, category: str, item: str, summary: str, recommendation: str) -> None:
    findings.append(Finding(severity, category, item, summary, recommendation))


def audit_inventory(path: Path) -> AuditReport:
    records = read_inventory(path)
    findings: list[Finding] = []
    parsed: list[tuple[SubnetRecord, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    seen_site_vlan: dict[tuple[str, str], SubnetRecord] = {}

    for record in records:
        label = f"{record.site} VLAN {record.vlan_id} {record.name}".strip()
        network = parse_network(record.cidr)
        if network is None:
            add_finding(findings, "critical", "invalid cidr", label, f"`{record.cidr}` is not a valid network.", "Correct the CIDR before using this inventory for automation.")
            continue
        parsed.append((record, network))

        site_vlan = (record.site.lower(), record.vlan_id)
        if site_vlan in seen_site_vlan:
            add_finding(findings, "high", "duplicate vlan", label, f"VLAN ID {record.vlan_id} appears more than once at {record.site}.", "Confirm whether this is a duplicate row or a real routed design exception.")
        seen_site_vlan[site_vlan] = record

        gateway = parse_address(record.gateway)
        if gateway is None:
            add_finding(findings, "high", "gateway", label, "Gateway address is missing or invalid.", "Add a valid gateway address or document why this network has no gateway.")
        elif gateway not in network:
            add_finding(findings, "high", "gateway", label, f"Gateway `{gateway}` is outside `{network}`.", "Correct the gateway or subnet record.")

        dhcp_start = parse_address(record.dhcp_start)
        dhcp_end = parse_address(record.dhcp_end)
        if bool(record.dhcp_start) != bool(record.dhcp_end):
            add_finding(findings, "medium", "dhcp scope", label, "DHCP start/end is incomplete.", "Provide both DHCP start and end, or leave both blank for static-only networks.")
        elif dhcp_start and dhcp_end:
            if dhcp_start.version != network.version or dhcp_end.version != network.version:
                add_finding(findings, "high", "dhcp scope", label, "DHCP range IP version does not match the subnet.", "Correct the DHCP range.")
            elif dhcp_start not in network or dhcp_end not in network:
                add_finding(findings, "high", "dhcp scope", label, f"DHCP range `{dhcp_start}` - `{dhcp_end}` is outside `{network}`.", "Correct the DHCP scope before deployment.")
            elif int(dhcp_start) > int(dhcp_end):
                add_finding(findings, "medium", "dhcp scope", label, "DHCP start is greater than DHCP end.", "Swap or correct the DHCP range values.")
            elif gateway and gateway in {dhcp_start, dhcp_end}:
                add_finding(findings, "medium", "dhcp scope", label, "DHCP range touches the gateway address.", "Reserve gateway and infrastructure addresses outside the client pool.")

        if not record.owner:
            add_finding(findings, "medium", "ownership", label, "Subnet owner is missing.", "Assign an owner so cleanup and incident follow-up have a responsible team.")
        if not record.purpose:
            add_finding(findings, "low", "documentation", label, "Subnet purpose is missing.", "Document what the network is for and what belongs in it.")
        if network.prefixlen <= 16:
            add_finding(findings, "low", "large subnet", label, f"`{network}` is a large network.", "Confirm this is intentional and documented.")

    for index, (left_record, left_network) in enumerate(parsed):
        for right_record, right_network in parsed[index + 1 :]:
            if left_network.version != right_network.version:
                continue
            if left_network.overlaps(right_network):
                left_label = f"{left_record.site} VLAN {left_record.vlan_id} {left_record.name}".strip()
                right_label = f"{right_record.site} VLAN {right_record.vlan_id} {right_record.name}".strip()
                severity = "high" if left_record.site.lower() == right_record.site.lower() else "medium"
                add_finding(
                    findings,
                    severity,
                    "overlap",
                    left_label,
                    f"`{left_network}` overlaps `{right_network}` used by {right_label}.",
                    "Resolve overlapping networks or document the routing/NAT boundary that makes this safe.",
                )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (severity_order.get(item.severity, 9), item.category, item.item))
    summary = {
        "critical": sum(1 for finding in findings if finding.severity == "critical"),
        "high": sum(1 for finding in findings if finding.severity == "high"),
        "medium": sum(1 for finding in findings if finding.severity == "medium"),
        "low": sum(1 for finding in findings if finding.severity == "low"),
    }
    return AuditReport(str(path), len(records), summary, findings)


def markdown(report: AuditReport) -> str:
    lines = [
        "# Subnet Inventory Audit",
        "",
        f"Source: `{report.source}`",
        f"Subnets reviewed: `{report.subnet_count}`",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity, count in report.summary.items():
        lines.append(f"| {severity.upper()} | {count} |")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings generated from the provided inventory.")
    else:
        lines.extend(["| Severity | Category | Item | Summary | Recommendation |", "| --- | --- | --- | --- | --- |"])
        for finding in report.findings:
            lines.append(f"| {finding.severity.upper()} | {finding.category} | {finding.item} | {finding.summary} | {finding.recommendation} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a subnet/VLAN inventory CSV.")
    parser.add_argument("inventory", type=Path, help="CSV inventory to audit")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown")
    parser.add_argument("--output", type=Path, help="Optional report output path")
    args = parser.parse_args()

    try:
        report = audit_inventory(args.inventory)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    content = json.dumps(asdict(report), indent=2) if args.json else markdown(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        print(f"Wrote report to {args.output}")
    else:
        print(content)

    return 1 if report.summary["critical"] or report.summary["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
