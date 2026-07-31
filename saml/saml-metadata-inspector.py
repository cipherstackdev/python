#!/usr/bin/env python3
"""Inspect SAML metadata and summarize identity provider or service provider details."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:  # pragma: no cover - handled at runtime for users.
    x509 = None
    default_backend = None


NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


@dataclass(frozen=True)
class CertificateSummary:
    use: str
    subject: str | None
    issuer: str | None
    serial_number: str | None
    not_before: str | None
    not_after: str | None
    sha256: str
    days_remaining: int | None
    warning: str | None


@dataclass(frozen=True)
class MetadataSummary:
    entity_id: str | None
    valid_until: str | None
    cache_duration: str | None
    roles: list[str]
    name_id_formats: list[str]
    single_sign_on_services: list[dict[str, str]]
    single_logout_services: list[dict[str, str]]
    assertion_consumer_services: list[dict[str, str]]
    certificates: list[CertificateSummary]


def text_or_none(element: ET.Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    value = element.text.strip()
    return value or None


def endpoint_summary(element: ET.Element) -> dict[str, str]:
    fields = {}
    for key in ("Binding", "Location", "ResponseLocation", "index", "isDefault"):
        if key in element.attrib:
            fields[key] = element.attrib[key]
    return fields


def parse_certificate(raw_text: str, use: str, warn_days: int) -> CertificateSummary:
    compact = "".join(raw_text.split())
    der = base64.b64decode(compact)
    fingerprint = hashlib.sha256(der).hexdigest()

    if x509 is None or default_backend is None:
        return CertificateSummary(
            use=use,
            subject=None,
            issuer=None,
            serial_number=None,
            not_before=None,
            not_after=None,
            sha256=fingerprint,
            days_remaining=None,
            warning="Install cryptography for certificate date and subject parsing.",
        )

    cert = x509.load_der_x509_certificate(der, default_backend())
    now = dt.datetime.now(dt.timezone.utc)
    not_after = cert.not_valid_after_utc
    days_remaining = (not_after - now).days
    warning = None
    if days_remaining < 0:
        warning = "Certificate is expired."
    elif days_remaining <= warn_days:
        warning = f"Certificate expires within {warn_days} days."

    return CertificateSummary(
        use=use,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=hex(cert.serial_number),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=not_after.isoformat(),
        sha256=fingerprint,
        days_remaining=days_remaining,
        warning=warning,
    )


def inspect_metadata(path: Path, warn_days: int) -> MetadataSummary:
    root = ET.parse(path).getroot()
    entity = root
    if root.tag.endswith("EntitiesDescriptor"):
        entity = root.find("md:EntityDescriptor", NS)
        if entity is None:
            raise ValueError("No EntityDescriptor found in EntitiesDescriptor.")

    roles = []
    for role_name in ("IDPSSODescriptor", "SPSSODescriptor", "AttributeAuthorityDescriptor"):
        if entity.find(f"md:{role_name}", NS) is not None:
            roles.append(role_name)

    name_ids = sorted(
        {
            value
            for value in (text_or_none(element) for element in entity.findall(".//md:NameIDFormat", NS))
            if value
        }
    )

    sso = [endpoint_summary(element) for element in entity.findall(".//md:SingleSignOnService", NS)]
    slo = [endpoint_summary(element) for element in entity.findall(".//md:SingleLogoutService", NS)]
    acs = [endpoint_summary(element) for element in entity.findall(".//md:AssertionConsumerService", NS)]

    certificates = []
    for key_descriptor in entity.findall(".//md:KeyDescriptor", NS):
        use = key_descriptor.attrib.get("use", "unspecified")
        cert_text = text_or_none(key_descriptor.find(".//ds:X509Certificate", NS))
        if cert_text:
            certificates.append(parse_certificate(cert_text, use, warn_days))

    return MetadataSummary(
        entity_id=entity.attrib.get("entityID"),
        valid_until=entity.attrib.get("validUntil"),
        cache_duration=entity.attrib.get("cacheDuration"),
        roles=roles,
        name_id_formats=name_ids,
        single_sign_on_services=sso,
        single_logout_services=slo,
        assertion_consumer_services=acs,
        certificates=certificates,
    )


def print_summary(summary: MetadataSummary) -> None:
    print("SAML Metadata Summary")
    print("=" * 72)
    print(f"Entity ID:      {summary.entity_id or '(missing)'}")
    print(f"Valid Until:    {summary.valid_until or '(not set)'}")
    print(f"Cache Duration: {summary.cache_duration or '(not set)'}")
    print(f"Roles:          {', '.join(summary.roles) if summary.roles else '(none found)'}")

    print("\nNameID Formats")
    for value in summary.name_id_formats or ["(none found)"]:
        print(f"- {value}")

    def print_endpoints(title: str, endpoints: list[dict[str, str]]) -> None:
        print(f"\n{title}")
        if not endpoints:
            print("- (none found)")
            return
        for endpoint in endpoints:
            location = endpoint.get("Location", "(missing Location)")
            binding = endpoint.get("Binding", "(missing Binding)")
            extras = ", ".join(f"{k}={v}" for k, v in endpoint.items() if k not in {"Location", "Binding"})
            suffix = f" [{extras}]" if extras else ""
            print(f"- {binding} -> {location}{suffix}")

    print_endpoints("Single Sign-On Services", summary.single_sign_on_services)
    print_endpoints("Single Logout Services", summary.single_logout_services)
    print_endpoints("Assertion Consumer Services", summary.assertion_consumer_services)

    print("\nCertificates")
    if not summary.certificates:
        print("- (none found)")
    for cert in summary.certificates:
        print(f"- Use: {cert.use}")
        print(f"  SHA256: {cert.sha256}")
        if cert.subject:
            print(f"  Subject: {cert.subject}")
        if cert.issuer:
            print(f"  Issuer: {cert.issuer}")
        if cert.not_after:
            print(f"  Not After: {cert.not_after} ({cert.days_remaining} days remaining)")
        if cert.warning:
            print(f"  Warning: {cert.warning}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect SAML metadata XML.")
    parser.add_argument("metadata", type=Path, help="Path to SAML metadata XML")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of human-readable output")
    parser.add_argument("--warn-days", type=int, default=45, help="Warn when certificates expire within this many days")
    args = parser.parse_args()

    try:
        summary = inspect_metadata(args.metadata, args.warn_days)
    except (ET.ParseError, OSError, ValueError, base64.binascii.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(asdict(summary), indent=2))
    else:
        print_summary(summary)

    return 0


if __name__ == "__main__":
    sys.exit(main())
