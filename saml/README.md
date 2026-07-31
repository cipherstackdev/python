# SAML Utilities

Public-safe utilities for SAML metadata review and identity troubleshooting.

## Scripts

| Script | Purpose |
| --- | --- |
| `saml-metadata-inspector.py` | Parses SAML metadata XML and summarizes entity ID, SSO/SLO endpoints, NameID formats, signing/encryption certificates, and certificate expiration dates. |

## Setup

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python saml/saml-metadata-inspector.py metadata.xml
python saml/saml-metadata-inspector.py metadata.xml --json
python saml/saml-metadata-inspector.py metadata.xml --warn-days 60
```

## Public Safety Notes

- Metadata can reveal tenant names, domains, certificate details, and SSO endpoints.
- Do not commit customer metadata files.
- Use sanitized samples when documenting output.
- This utility inspects metadata; it does not validate trust or test live SSO flows.
