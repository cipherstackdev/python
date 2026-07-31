#!/usr/bin/env python3
"""Audit expected DNS records from a CSV file."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - handled at runtime.
    dns = None


REQUIRED_COLUMNS = {"name", "type"}


@dataclass(frozen=True)
class DnsTarget:
    name: str
    record_type: str
    expected_contains: str
    owner: str
    notes: str


@dataclass(frozen=True)
class DnsResult:
    name: str
    record_type: str
    status: str
    values: list[str]
    expected_contains: str
    finding: str
    owner: str
    notes: str


def require_dns() -> None:
    if dns is None:
        raise RuntimeError("dnspython is required. Install dependencies with: pip install -r requirements.txt")


def read_targets(path: Path) -> list[DnsTarget]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [{key.strip(): (value or "").strip() for key, value in row.items()} for row in csv.DictReader(handle)]
    if not rows:
        raise ValueError(f"{path} has no rows.")
    missing = REQUIRED_COLUMNS.difference(rows[0].keys())
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")
    return [
        DnsTarget(
            name=row["name"].rstrip("."),
            record_type=row["type"].upper(),
            expected_contains=row.get("expected_contains", ""),
            owner=row.get("owner", ""),
            notes=row.get("notes", ""),
        )
        for row in rows
    ]


def normalize_answer(answer: object) -> str:
    value = str(answer).strip().rstrip(".")
    return " ".join(value.split())


def resolve_records(target: DnsTarget, timeout: float) -> DnsResult:
    require_dns()
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(target.name, target.record_type)
        values = sorted(normalize_answer(answer) for answer in answers)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as exc:
        return DnsResult(
            target.name,
            target.record_type,
            "fail",
            [],
            target.expected_contains,
            f"No {target.record_type} record found: {exc.__class__.__name__}",
            target.owner,
            target.notes,
        )
    except dns.exception.Timeout:
        return DnsResult(
            target.name,
            target.record_type,
            "fail",
            [],
            target.expected_contains,
            "DNS query timed out.",
            target.owner,
            target.notes,
        )

    if target.expected_contains:
        haystack = "\n".join(values).lower()
        expected = target.expected_contains.lower()
        if expected in haystack:
            status = "pass"
            finding = "Expected value found."
        else:
            status = "fail"
            finding = "Record exists, but expected value was not found."
    else:
        status = "pass"
        finding = "Record exists."

    return DnsResult(
        target.name,
        target.record_type,
        status,
        values,
        target.expected_contains,
        finding,
        target.owner,
        target.notes,
    )


def markdown(results: list[DnsResult], source: Path) -> str:
    passed = sum(1 for result in results if result.status == "pass")
    failed = len(results) - passed
    lines = [
        "# DNS Record Audit",
        "",
        f"Source: `{source}`",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Records | {len(results)} |",
        f"| Passed | {passed} |",
        f"| Failed | {failed} |",
        "",
        "## Results",
        "",
        "| Status | Name | Type | Finding | Values |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in sorted(results, key=lambda item: (item.status, item.name, item.record_type)):
        values = "<br>".join(result.values) if result.values else ""
        lines.append(f"| {result.status.upper()} | `{result.name}` | {result.record_type} | {result.finding} | {values} |")
    lines.append("")
    return "\n".join(lines)


def write_csv(path: Path, results: list[DnsResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(DnsResult.__dataclass_fields__.keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row["values"] = ";".join(result.values)
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit expected DNS records from CSV.")
    parser.add_argument("records", type=Path, help="CSV with name, type, optional expected_contains, owner, notes")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--csv-output", type=Path, help="Optional CSV output path")
    parser.add_argument("--output", type=Path, help="Optional Markdown or JSON output path")
    args = parser.parse_args()

    try:
        targets = read_targets(args.records)
        results = [resolve_records(target, args.timeout) for target in targets]
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.csv_output:
        write_csv(args.csv_output, results)
        print(f"Wrote CSV report to {args.csv_output}")

    content = json.dumps([asdict(result) for result in results], indent=2) if args.json else markdown(results, args.records)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        print(f"Wrote report to {args.output}")
    elif not args.csv_output or args.json:
        print(content)

    return 1 if any(result.status == "fail" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
