# DNS Record Audit

Source: `network/examples/dns-records.csv`

| Metric | Count |
| --- | ---: |
| Records | 4 |
| Passed | 4 |
| Failed | 0 |

## Results

| Status | Name | Type | Finding | Values |
| --- | --- | --- | --- | --- |
| PASS | `example.com` | A | Record exists. | 93.184.216.34 |
| PASS | `example.com` | MX | Record exists. | 10 mail.example.com |
| PASS | `_dmarc.example.com` | TXT | Expected value found. | "v=DMARC1; p=none; rua=mailto:dmarc@example.com" |
| PASS | `www.example.com` | CNAME | Expected value found. | example.com |
