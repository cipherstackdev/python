# Network Admin Utilities

Public-safe Python tools for external checks, audit preparation, and network administration reporting.

## Scripts

| Script | Purpose |
| --- | --- |
| `domain-posture-audit.py` | Audits public DNS, email security records, HTTPS TLS certificate health, and web security headers for a domain. |

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

## What It Checks

- DNS basics: `A`, `AAAA`, `NS`, and `CAA`.
- Email posture: `MX`, SPF, DMARC, MTA-STS, and TLS-RPT.
- HTTPS TLS: handshake, protocol, issuer, subject, and expiration window.
- Web headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.

## Public Safety Notes

- Run this only against domains you own or have permission to assess.
- Do not publish client reports unless the customer has approved the output.
- Treat IP addresses, certificate details, and mail routing records as potentially sensitive in a client context.
