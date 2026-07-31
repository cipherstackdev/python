#!/usr/bin/env python3
"""Audit TCP reachability for hosts and ports from a CSV file."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


REQUIRED_COLUMNS = {"name", "host", "port"}


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    port: int
    protocol: str
    expected: str
    owner: str
    notes: str


@dataclass(frozen=True)
class CheckResult:
    name: str
    host: str
    port: int
    protocol: str
    expected: str
    owner: str
    status: str
    seconds: float | None
    resolved_addresses: list[str]
    tls_subject: str
    tls_issuer: str
    tls_not_after: str
    finding: str
    notes: str


def read_targets(path: Path) -> list[Target]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [{key.strip(): (value or "").strip() for key, value in row.items()} for row in csv.DictReader(handle)]
    if not rows:
        raise ValueError(f"{path} has no rows.")
    missing = REQUIRED_COLUMNS.difference(rows[0].keys())
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")

    targets = []
    for row_number, row in enumerate(rows, start=2):
        try:
            port = int(row["port"])
        except ValueError as exc:
            raise ValueError(f"{path}:{row_number} has invalid port: {row['port']}") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"{path}:{row_number} has port outside 1-65535: {port}")
        protocol = (row.get("protocol") or "tcp").lower()
        if protocol not in {"tcp", "tls"}:
            raise ValueError(f"{path}:{row_number} protocol must be tcp or tls.")
        expected = (row.get("expected") or "open").lower()
        if expected not in {"open", "closed"}:
            raise ValueError(f"{path}:{row_number} expected must be open or closed.")
        targets.append(
            Target(
                name=row["name"],
                host=row["host"],
                port=port,
                protocol=protocol,
                expected=expected,
                owner=row.get("owner", ""),
                notes=row.get("notes", ""),
            )
        )
    return targets


def resolve_host(host: str) -> list[str]:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    }
    return sorted(addresses)


def certificate_summary(sock: ssl.SSLSocket) -> tuple[str, str, str]:
    cert = sock.getpeercert()
    subject = ", ".join("=".join(item) for group in cert.get("subject", []) for item in group)
    issuer = ", ".join("=".join(item) for group in cert.get("issuer", []) for item in group)
    not_after = str(cert.get("notAfter", ""))
    return subject, issuer, not_after


def check_target(target: Target, timeout: float) -> CheckResult:
    started = time.monotonic()
    resolved_addresses: list[str] = []
    tls_subject = ""
    tls_issuer = ""
    tls_not_after = ""

    try:
        resolved_addresses = resolve_host(target.host)
    except OSError as exc:
        is_expected = target.expected == "closed"
        return CheckResult(
            target.name,
            target.host,
            target.port,
            target.protocol,
            target.expected,
            target.owner,
            "pass" if is_expected else "fail",
            None,
            [],
            "",
            "",
            "",
            f"DNS lookup failed: {exc}",
            target.notes,
        )

    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as raw_sock:
            if target.protocol == "tls":
                context = ssl.create_default_context()
                with context.wrap_socket(raw_sock, server_hostname=target.host) as tls_sock:
                    tls_subject, tls_issuer, tls_not_after = certificate_summary(tls_sock)
            seconds = round(time.monotonic() - started, 3)
            status = "pass" if target.expected == "open" else "fail"
            finding = "Port is reachable." if target.expected == "open" else "Port is reachable but expected closed."
    except (OSError, ssl.SSLError) as exc:
        seconds = round(time.monotonic() - started, 3)
        status = "pass" if target.expected == "closed" else "fail"
        finding = f"Connection failed: {exc}" if target.expected == "open" else "Port is not reachable."

    return CheckResult(
        target.name,
        target.host,
        target.port,
        target.protocol,
        target.expected,
        target.owner,
        status,
        seconds,
        resolved_addresses,
        tls_subject,
        tls_issuer,
        tls_not_after,
        finding,
        target.notes,
    )


def markdown(results: list[CheckResult], source: Path) -> str:
    passed = sum(1 for result in results if result.status == "pass")
    failed = len(results) - passed
    lines = [
        "# TCP Reachability Audit",
        "",
        f"Source: `{source}`",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Targets | {len(results)} |",
        f"| Passed | {passed} |",
        f"| Failed | {failed} |",
        "",
        "## Results",
        "",
        "| Status | Name | Host | Port | Expected | Finding |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for result in sorted(results, key=lambda item: (item.status, item.name, item.host, item.port)):
        lines.append(
            f"| {result.status.upper()} | {result.name} | `{result.host}` | {result.port} | "
            f"{result.expected} | {result.finding} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_csv(path: Path, results: list[CheckResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()) if results else list(CheckResult.__dataclass_fields__.keys()))
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row["resolved_addresses"] = ";".join(result.resolved_addresses)
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit TCP reachability for hosts and ports from CSV.")
    parser.add_argument("targets", type=Path, help="CSV with name, host, port, optional protocol, expected, owner, notes")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout in seconds")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent workers")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown output")
    parser.add_argument("--csv-output", type=Path, help="Optional CSV output path")
    parser.add_argument("--output", type=Path, help="Optional JSON or Markdown output path")
    args = parser.parse_args()

    try:
        targets = read_targets(args.targets)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_target, target, args.timeout) for target in targets]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]

    results = sorted(results, key=lambda item: (item.status, item.name, item.host, item.port))

    if args.csv_output:
        write_csv(args.csv_output, results)
        print(f"Wrote CSV report to {args.csv_output}")

    if args.json:
        content = json.dumps([asdict(result) for result in results], indent=2)
    else:
        content = markdown(results, args.targets)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        print(f"Wrote report to {args.output}")
    elif not args.csv_output or args.json or args.markdown:
        print(content)

    return 1 if any(result.status == "fail" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
