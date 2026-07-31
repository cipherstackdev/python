#!/usr/bin/env python3
"""Audit public DNS, email security, TLS, and web headers for a domain."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import requests

try:
    import dns.resolver
except ImportError:  # pragma: no cover - handled at runtime.
    dns = None


SECURITY_HEADERS = {
    "strict-transport-security": "HTTP Strict Transport Security",
    "content-security-policy": "Content Security Policy",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "MIME sniffing protection",
    "referrer-policy": "Referrer policy",
    "permissions-policy": "Browser permissions policy",
}


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    summary: str
    details: list[str]


@dataclass(frozen=True)
class AuditReport:
    domain: str
    generated_at: str
    checks: list[CheckResult]


def require_dns() -> None:
    if dns is None:
        raise RuntimeError("dnspython is required. Install dependencies with: pip install -r requirements.txt")


def resolve_records(name: str, record_type: str, timeout: float) -> list[str]:
    require_dns()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(name, record_type)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return ["DNS_TIMEOUT"]

    return sorted(str(answer).strip().rstrip(".") for answer in answers)


def has_dns_answers(records: list[str]) -> bool:
    return bool(records) and records != ["DNS_TIMEOUT"]


def check_dns_basics(domain: str, timeout: float) -> CheckResult:
    records = {
        "A": resolve_records(domain, "A", timeout),
        "AAAA": resolve_records(domain, "AAAA", timeout),
        "NS": resolve_records(domain, "NS", timeout),
        "CAA": resolve_records(domain, "CAA", timeout),
    }
    details = [f"{record_type}: {', '.join(values) if values else '(none found)'}" for record_type, values in records.items()]

    if has_dns_answers(records["A"]) or has_dns_answers(records["AAAA"]):
        status = "pass"
        summary = "Domain resolves to public web records."
    else:
        status = "fail"
        summary = "Domain does not have A or AAAA records."

    if not records["CAA"]:
        details.append("Recommendation: add CAA records if you want to restrict certificate issuance.")

    return CheckResult("DNS basics", status, summary, details)


def check_email_security(domain: str, timeout: float) -> CheckResult:
    mx_records = resolve_records(domain, "MX", timeout)
    txt_records = resolve_records(domain, "TXT", timeout)
    dmarc_records = resolve_records(f"_dmarc.{domain}", "TXT", timeout)
    mta_sts_records = resolve_records(f"_mta-sts.{domain}", "TXT", timeout)
    tls_rpt_records = resolve_records(f"_smtp._tls.{domain}", "TXT", timeout)

    spf_records = [record for record in txt_records if "v=spf1" in record.lower()]
    dmarc_policy = next((record for record in dmarc_records if "v=dmarc1" in record.lower()), None)

    details = [
        f"MX: {', '.join(mx_records) if mx_records else '(none found)'}",
        f"SPF: {', '.join(spf_records) if spf_records else '(none found)'}",
        f"DMARC: {dmarc_policy or '(none found)'}",
        f"MTA-STS: {', '.join(mta_sts_records) if mta_sts_records else '(none found)'}",
        f"TLS-RPT: {', '.join(tls_rpt_records) if tls_rpt_records else '(none found)'}",
    ]

    findings = []
    if not has_dns_answers(mx_records):
        findings.append("No MX records found.")
    if len(spf_records) == 0:
        findings.append("No SPF record found.")
    elif len(spf_records) > 1:
        findings.append("Multiple SPF records found; publish only one SPF record.")
    if not dmarc_policy:
        findings.append("No DMARC record found.")
    elif "p=none" in dmarc_policy.lower():
        findings.append("DMARC is monitoring only; consider quarantine or reject after validation.")
    if not mta_sts_records:
        findings.append("MTA-STS record not found.")
    if not tls_rpt_records:
        findings.append("TLS-RPT record not found.")

    if not findings:
        status = "pass"
        summary = "Email security records are present."
    elif len(findings) <= 2:
        status = "warn"
        summary = "Email security is mostly configured, with a few gaps."
    else:
        status = "fail"
        summary = "Email security records need attention."

    details.extend(f"Finding: {finding}" for finding in findings)
    return CheckResult("Email security", status, summary, details)


def check_tls(domain: str, port: int, timeout: float, warn_days: int) -> CheckResult:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
    except (OSError, ssl.SSLError) as exc:
        return CheckResult("HTTPS TLS", "fail", "Could not complete a TLS handshake.", [str(exc)])

    not_after_text = cert.get("notAfter")
    if not not_after_text:
        return CheckResult("HTTPS TLS", "warn", "Certificate did not include a readable expiration date.", [f"Protocol: {protocol}"])

    not_after = dt.datetime.strptime(not_after_text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    days_remaining = (not_after - dt.datetime.now(dt.timezone.utc)).days
    subject = ", ".join("=".join(item) for group in cert.get("subject", []) for item in group)
    issuer = ", ".join("=".join(item) for group in cert.get("issuer", []) for item in group)

    details = [
        f"Protocol: {protocol}",
        f"Subject: {subject or '(not provided)'}",
        f"Issuer: {issuer or '(not provided)'}",
        f"Expires: {not_after.isoformat()} ({days_remaining} days remaining)",
    ]

    if days_remaining < 0:
        return CheckResult("HTTPS TLS", "fail", "TLS certificate is expired.", details)
    if days_remaining <= warn_days:
        return CheckResult("HTTPS TLS", "warn", f"TLS certificate expires within {warn_days} days.", details)
    return CheckResult("HTTPS TLS", "pass", "TLS certificate is valid beyond the warning window.", details)


def check_security_headers(domain: str, timeout: float) -> CheckResult:
    url = f"https://{domain}"
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return CheckResult("Web security headers", "fail", "Could not fetch the HTTPS site.", [str(exc)])

    headers = {key.lower(): value for key, value in response.headers.items()}
    details = [
        f"HTTP status: {response.status_code}",
        f"Final URL: {response.url}",
    ]

    missing = []
    for header, description in SECURITY_HEADERS.items():
        if header in headers:
            details.append(f"{description}: present")
        else:
            missing.append(description)
            details.append(f"{description}: missing")

    if not missing:
        status = "pass"
        summary = "Recommended security headers are present."
    elif len(missing) <= 2:
        status = "warn"
        summary = "Most security headers are present."
    else:
        status = "warn"
        summary = "Several recommended security headers are missing."

    return CheckResult("Web security headers", status, summary, details)


def build_report(domain: str, timeout: float, warn_days: int) -> AuditReport:
    checks = [
        check_dns_basics(domain, timeout),
        check_email_security(domain, timeout),
        check_tls(domain, 443, timeout, warn_days),
        check_security_headers(domain, timeout),
    ]
    return AuditReport(
        domain=domain,
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        checks=checks,
    )


def print_text(report: AuditReport) -> None:
    print(f"Domain Posture Audit: {report.domain}")
    print(f"Generated: {report.generated_at}")
    print("=" * 72)
    for check in report.checks:
        print(f"\n[{check.status.upper()}] {check.name}")
        print(check.summary)
        for detail in check.details:
            print(f"- {detail}")


def markdown(report: AuditReport) -> str:
    lines = [
        f"# Domain Posture Audit: {report.domain}",
        "",
        f"Generated: `{report.generated_at}`",
        "",
        "| Check | Status | Summary |",
        "| --- | --- | --- |",
    ]
    for check in report.checks:
        lines.append(f"| {check.name} | {check.status.upper()} | {check.summary} |")

    for check in report.checks:
        lines.extend(["", f"## {check.name}", "", f"Status: **{check.status.upper()}**", "", check.summary, ""])
        lines.extend(f"- {detail}" for detail in check.details)

    lines.append("")
    return "\n".join(lines)


def write_output(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="https")
    domain = parsed.netloc or parsed.path
    return domain.split("@")[-1].split(":")[0].strip("/")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit public DNS, email security, TLS, and web headers for a domain.")
    parser.add_argument("domain", help="Domain to audit, such as example.com")
    parser.add_argument("--timeout", type=float, default=8.0, help="Network timeout in seconds")
    parser.add_argument("--warn-days", type=int, default=45, help="Warn when TLS certificates expire within this many days")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown report output")
    parser.add_argument("--output", help="Optional file path for JSON or Markdown output")
    args = parser.parse_args()

    domain = normalize_domain(args.domain)
    if not domain:
        print("Error: domain is required.", file=sys.stderr)
        return 2
    try:
        report = build_report(domain, args.timeout, args.warn_days)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        content = json.dumps(asdict(report), indent=2)
    elif args.markdown:
        content = markdown(report)
    else:
        print_text(report)
        return 1 if any(check.status == "fail" for check in report.checks) else 0

    if args.output:
        write_output(args.output, content)
        print(f"Wrote report to {args.output}")
    else:
        print(content)

    return 1 if any(check.status == "fail" for check in report.checks) else 0


if __name__ == "__main__":
    sys.exit(main())
