# TCP Reachability Audit

Source: `network/examples/tcp-targets.csv`

| Metric | Count |
| --- | ---: |
| Targets | 3 |
| Passed | 3 |
| Failed | 0 |

## Results

| Status | Name | Host | Port | Expected | Finding |
| --- | --- | --- | ---: | --- | --- |
| PASS | Closed Demo | `example.com` | 65000 | closed | Port is not reachable. |
| PASS | Public DNS | `1.1.1.1` | 53 | open | Port is reachable. |
| PASS | Public HTTPS | `example.com` | 443 | open | Port is reachable. |
