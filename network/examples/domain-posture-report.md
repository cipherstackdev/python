# Domain Posture Audit: example.com

Generated: `2026-07-31T00:00:00+00:00`

| Check | Status | Summary |
| --- | --- | --- |
| DNS basics | PASS | Domain resolves to public web records. |
| Email security | WARN | Email security is mostly configured, with a few gaps. |
| HTTPS TLS | PASS | TLS certificate is valid beyond the warning window. |
| Web security headers | WARN | Several recommended security headers are missing. |

## DNS basics

Status: **PASS**

Domain resolves to public web records.

- A: 203.0.113.10
- AAAA: 2001:db8::10
- NS: ns1.example.net, ns2.example.net
- CAA: 0 issue "letsencrypt.org"

## Email security

Status: **WARN**

Email security is mostly configured, with a few gaps.

- MX: 10 mail.example.com
- SPF: "v=spf1 include:example.net -all"
- DMARC: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
- MTA-STS: (none found)
- TLS-RPT: "v=TLSRPTv1; rua=mailto:tls-report@example.com"
- Finding: MTA-STS record not found.

## HTTPS TLS

Status: **PASS**

TLS certificate is valid beyond the warning window.

- Protocol: TLSv1.3
- Subject: commonName=example.com
- Issuer: organizationName=Example Certificate Authority
- Expires: 2026-12-31T23:59:59+00:00 (153 days remaining)

## Web security headers

Status: **WARN**

Several recommended security headers are missing.

- HTTP status: 200
- Final URL: https://example.com/
- HTTP Strict Transport Security: present
- Content Security Policy: missing
- Clickjacking protection: present
- MIME sniffing protection: present
- Referrer policy: missing
- Browser permissions policy: missing
