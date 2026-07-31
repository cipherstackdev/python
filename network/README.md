# Network Admin Utilities

Public-safe Python tools for external checks, audit preparation, and network administration reporting.

## Scripts

| Script | Purpose |
| --- | --- |
| `domain-posture-audit.py` | Audits public DNS, email security records, HTTPS TLS certificate health, and web security headers for a domain. |
| `dns-record-audit.py` | Validates expected DNS records from CSV for migrations, cutovers, and cleanup checks. |
| `subnet-inventory-audit.py` | Reviews subnet/VLAN inventory CSVs for invalid CIDRs, overlaps, gateway issues, DHCP range problems, and missing ownership. |
| `tcp-reachability-audit.py` | Checks expected TCP/TLS service reachability from a CSV and reports pass/fail results. |

## Setup

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Human-readable output:

```bash
python network/domain-posture-audit.py example.com
```

Client-ready Markdown:

```bash
python network/domain-posture-audit.py example.com --markdown --output example-domain-posture.md
```

Automation-friendly JSON:

```bash
python network/domain-posture-audit.py example.com --json
```

DNS record validation:

```bash
python network/dns-record-audit.py network/examples/dns-records.csv
python network/dns-record-audit.py network/examples/dns-records.csv --csv-output dns-results.csv
python network/dns-record-audit.py network/examples/dns-records.csv --json
```

Subnet/VLAN inventory review:

```bash
python network/subnet-inventory-audit.py network/examples/subnet-inventory.csv
python network/subnet-inventory-audit.py network/examples/subnet-inventory.csv --output subnet-audit.md
python network/subnet-inventory-audit.py network/examples/subnet-inventory.csv --json
```

TCP reachability checks:

```bash
python network/tcp-reachability-audit.py network/examples/tcp-targets.csv
python network/tcp-reachability-audit.py network/examples/tcp-targets.csv --csv-output tcp-results.csv
python network/tcp-reachability-audit.py network/examples/tcp-targets.csv --json
```

## What It Checks

- DNS basics: `A`, `AAAA`, `NS`, and `CAA`.
- DNS record audit: expected record presence and expected-value checks from CSV.
- Email posture: `MX`, SPF, DMARC, MTA-STS, and TLS-RPT.
- HTTPS TLS: handshake, protocol, issuer, subject, and expiration window.
- Web headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Subnet inventory: duplicate site/VLAN pairs, overlapping networks, invalid gateway values, DHCP range problems, missing owners, and missing purpose notes.
- TCP reachability: DNS resolution, open/closed expectation checks, optional TLS certificate summary, concurrent service validation.

## Public Safety Notes

- Run this only against domains you own or have permission to assess.
- Do not publish client reports unless the customer has approved the output.
- Treat IP addresses, certificate details, and mail routing records as potentially sensitive in a client context.
- Sanitize private subnet plans before publishing example reports.
- Sanitize internal hostnames, IP addresses, and firewall validation results before publishing.
