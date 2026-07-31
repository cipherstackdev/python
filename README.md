# Python

Small Python utilities for link checks, data cleanup, reporting, and admin workflow automation.

## Utilities

| Script | Purpose |
| --- | --- |
| `link-verifier.py` | Checks URLs from files or command-line input and reports reachable, redirected, and failed links. |

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
```

## Public Safety Notes

- Do not publish scanned output that includes private client URLs.
- Keep API tokens in environment variables or local secret stores, not in scripts.
- Prefer small tools with clear input/output over monolithic automation.
