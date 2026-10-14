# ICMP Types

These are the `icmp-type` names Aerleon accepts, with their type numbers. They come from `Term.ICMP_TYPE` in `aerleon/lib/aclgenerator.py`. Some generators rename them (see [Nftables](nftables.md#icmp-types)).

## IPv4

| Name | Type |
|---|---|
| `echo-reply` | 0 |
| `unreachable` | 3 |
| `source-quench` | 4 |
| `redirect` | 5 |
| `alternate-address` | 6 |
| `echo-request` | 8 |
| `router-advertisement` | 9 |
| `router-solicitation` | 10 |
| `time-exceeded` | 11 |
| `parameter-problem` | 12 |
| `timestamp-request` | 13 |
| `timestamp-reply` | 14 |
| `information-request` | 15 |
| `information-reply` | 16 |
| `mask-request` | 17 |
| `mask-reply` | 18 |
| `conversion-error` | 31 |
| `mobile-redirect` | 32 |

## IPv6

| Name | Type |
|---|---|
| `destination-unreachable` | 1 |
| `packet-too-big` | 2 |
| `time-exceeded` | 3 |
| `parameter-problem` | 4 |
| `echo-request` | 128 |
| `echo-reply` | 129 |
| `multicast-listener-query` | 130 |
| `multicast-listener-report` | 131 |
| `multicast-listener-done` | 132 |
| `router-solicit` | 133 |
| `router-advertisement` | 134 |
| `neighbor-solicit` | 135 |
| `neighbor-advertisement` | 136 |
| `redirect-message` | 137 |
| `router-renumbering` | 138 |
| `icmp-node-information-query` | 139 |
| `icmp-node-information-response` | 140 |
| `inverse-neighbor-discovery-solicitation` | 141 |
| `inverse-neighbor-discovery-advertisement` | 142 |
| `version-2-multicast-listener-report` | 143 |
| `home-agent-address-discovery-request` | 144 |
| `home-agent-address-discovery-reply` | 145 |
| `mobile-prefix-solicitation` | 146 |
| `mobile-prefix-advertisement` | 147 |
| `certification-path-solicitation` | 148 |
| `certification-path-advertisement` | 149 |
| `multicast-router-advertisement` | 151 |
| `multicast-router-solicitation` | 152 |
| `multicast-router-termination` | 153 |
