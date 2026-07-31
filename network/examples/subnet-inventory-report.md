# Subnet Inventory Audit

Source: `network/examples/subnet-inventory.csv`
Subnets reviewed: `6`

## Summary

| Severity | Count |
| --- | ---: |
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 2 |
| LOW | 2 |

## Findings

| Severity | Category | Item | Summary | Recommendation |
| --- | --- | --- | --- | --- |
| HIGH | duplicate vlan | HQ VLAN 20 Duplicate Voice | VLAN ID 20 appears more than once at HQ. | Confirm whether this is a duplicate row or a real routed design exception. |
| HIGH | gateway | Branch-A VLAN 30 Guest | Gateway `10.20.31.1` is outside `10.20.30.0/24`. | Correct the gateway or subnet record. |
| HIGH | overlap | HQ VLAN 20 Voice | `10.10.20.0/24` overlaps `10.10.20.0/24` used by HQ VLAN 20 Duplicate Voice. | Resolve overlapping networks or document the routing/NAT boundary that makes this safe. |
| MEDIUM | overlap | Branch-A VLAN 30 Guest | `10.20.30.0/24` overlaps `10.20.30.128/25` used by Branch-B VLAN 40 Cameras. | Resolve overlapping networks or document the routing/NAT boundary that makes this safe. |
| MEDIUM | ownership | Branch-C VLAN 50 Facilities | Subnet owner is missing. | Assign an owner so cleanup and incident follow-up have a responsible team. |
| LOW | documentation | Branch-C VLAN 50 Facilities | Subnet purpose is missing. | Document what the network is for and what belongs in it. |
| LOW | large subnet | Branch-C VLAN 50 Facilities | `10.30.0.0/16` is a large network. | Confirm this is intentional and documented. |
