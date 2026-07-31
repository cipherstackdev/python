# Python

Small Python utilities for link checks, data cleanup, reporting, and admin workflow automation.

## Utilities

| Script | Purpose |
| --- | --- |
| `link-verifier.py` | Checks URLs from files or command-line input and reports reachable, redirected, and failed links. |
| `network/domain-posture-audit.py` | Audits public DNS, email security records, HTTPS TLS certificate health, and web security headers for a domain. |
| `saml/saml-metadata-inspector.py` | Parses SAML metadata XML and summarizes entity ID, endpoints, NameID formats, and certificate details. |

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Examples

```bash
python link-verifier.py --url https://cipherstack.dev
python link-verifier.py --file README.md --verbose
python link-verifier.py docs/*.md --timeout 5 --workers 20
python network/domain-posture-audit.py example.com
python network/domain-posture-audit.py example.com --markdown --output report.md
python saml/saml-metadata-inspector.py metadata.xml
python saml/saml-metadata-inspector.py metadata.xml --json
```

## Public Safety Notes

- Do not publish scanned output that includes private client URLs.
- Run network posture checks only against domains you own or have permission to assess.
- Do not commit customer SAML metadata, tenant names, domains, certificates, or SSO endpoints unless they are intentionally public.
- Keep API tokens in environment variables or local secret stores, not in scripts.
- Prefer small tools with clear input/output over monolithic automation.
