# AclCheck

## Introduction

AclCheck is a tool bundled with Aerleon that can check which terms in an Aerleon policy would match a specific packet and what action or actions would be taken by the generated ACL. This is useful for verifying policy correctness, troubleshooting connectivity issues, and understanding the impact of policy changes.

## Command-Line Usage

The `aclcheck` command-line tool provides a way to quickly test traffic scenarios against a policy file.

### Basic Example

To check if traffic from `192.168.1.10` to `10.0.0.1` on TCP port `80` is allowed by a policy defined in `my_policy.yaml`:

```bash
aclcheck --policy-file ./policies/pol/my_policy.yaml --source 192.168.1.10 --destination 10.0.0.1 --protocol tcp --dport 80
```

The output will show the terms in the policy that match the specified traffic and the action (e.g., `accept`, `deny`, `next`) taken by those terms.

### Command-Line Arguments

The `aclcheck` tool accepts the following arguments:

*   `-p, --policy-file, --policy_file POL`: (Required) The policy file to examine.
*   `--definitions-directory, --definitions_directory DIR`: The directory where network and service definition files can be found. Defaults to `./def`.
*   `--base-directory, --base_directory DIR`: The base directory to use when resolving policy include paths. Defaults to `./policies`.
*   `--config-file, --config_file FILE`: Change the location searched for the configuration YAML file (`aerleon.yml`).
*   `-d, --destination IP`: Destination IP address. Defaults to `200.1.1.1`.
*   `-s, --source IP`: Source IP address. Defaults to `any`.
*   `--proto, --protocol PROTO`: Protocol (e.g., `tcp`, `udp`, `icmp`). Defaults to `any`.
*   `--dport, --destination-port PORT`: Destination port. Defaults to `80`.
*   `--sport, --source-port PORT`: Source port. Defaults to `1025`.
*   `--source-zone ZONE`: Source security/zone identifier. When provided, `AclCheck` will only match terms that either have no `source-zone` constraint or explicitly match this zone. Use the exact zone name as used in your policy (case-sensitive).
*   `--destination-zone ZONE`: Destination security/zone identifier. When provided, `AclCheck` will only match terms that either have no `destination-zone` constraint or explicitly match this zone. Use the exact zone name as used in your policy (case-sensitive).

### Detailed Example

Here's an example demonstrating the use of several options:

```bash
aclcheck --policy-file ./policies/pol/sample_cisco_lab.yaml \
         --definitions-directory ./def \
         --source 10.1.1.1 \
         --destination 172.16.1.5 \
         --protocol udp \
         --dport 53 \
         --sport 12345
```

This command will check the `sample_cisco_lab.yaml` policy, using definitions from the `./def` directory, for traffic from `10.1.1.1` (source port `12345`) to `172.16.1.5` (destination port `53`) using the UDP protocol. The output will indicate which terms in the policy match this traffic and what action or actions are taken.

## API Usage

Aerleon includes a Python interface for `AclCheck`, allowing for programmatic integration into other tools or automation workflows.

### Example

The following Python code demonstrates how to use the `AclCheck` API:

```python
from aerleon import api
from aerleon.lib import naming

# Define the policy as a Python dictionary
# This structure is the YAML policy file format.
# You could call yaml.safe_load to load your YAML policy into this format.
example_policy = {
    "filename": "my_api_policy_check",
    "filters": [
        {
            "header": {
                "targets": {"cisco": "test-filter"},
                "comment": "Sample filter for AclCheck API demo",
            },
            "terms": [
                {
                    "name": "allow-web-traffic",
                    "source-address": "INTERNAL_NETWORK",
                    "destination-address": "WEB_SERVERS",
                    "destination-port": "HTTP",
                    "protocol": "tcp",
                    "action": "accept",
                },
                {"name": "deny-all-else", "action": "deny"},
            ],
        }
    ],
}

# Define network and service names
# This structure is the YAML definition file format.
# You could call yaml.safe_load to load your YAML definitions into this format.
definitions_data = {
    "networks": {
        "INTERNAL_NETWORK": {"values": [{"address": "192.168.1.0/24"}]},
        "WEB_SERVERS": {"values": [{"address": "10.0.0.10/32"}, {"address": "10.0.0.11/32"}]},
    },
    "services": {"HTTP": [{"protocol": "tcp", "port": "80"}]},
}

# Create a Naming object and parse the definitions
defs = naming.Naming()
defs.ParseDefinitionsObject(definitions_data, "definitions_data")
# The second argument is used for debugging / error messages only

# Define the target packet
source_ip = "192.168.1.50"
destination_ip = "10.0.0.10"
protocol = "tcp"
destination_port = "80"
source_port = "49152"

try:
    # Perform the AclCheck API call
    summary = api.AclCheck(
        input_policy=example_policy,
        definitions=defs,
        src=source_ip,
        dst=destination_ip,
        sport=source_port,
        dport=destination_port,
        proto=protocol,
    )

    # Example: loop over the output and print to stdout
    # A more common behavior would be to inspect the `summary` object
    # directly to confirm whether the final action is 'accept' or 'deny'
    if summary:
        for filter_name, terms in summary.items():
            print(f"  Filter: {filter_name}")
            for term_name, match_details in terms.items():
                print(match_details['message'])
    else:
        print(
            f"No matching terms found for traffic from {source_ip}:{source_port} to {destination_ip}:{destination_port} ({protocol})."
        )

except Exception as e:
    print(f"An error occurred: {e}")

```

### Policy and Definitions Structure

*   **`input_policy` (dict):** This dictionary represents the Aerleon policy.
    *   `filename`: A string identifier for the policy (primarily for context in logs/errors).
    *   `filters`: A list of filter dictionaries. Each filter dictionary must contain:
        *   `header`: A dictionary defining the filter's targets (e.g., `{"cisco": "filter_name"}`). At least one target must be specified for the policy to be parsed correctly, even though `AclCheck` itself is platform-agnostic. It can also contain other header options like `comment`.
        *   `terms`: A list of term dictionaries. Each term defines specific match criteria (like `source-address`, `destination-port`, `protocol`) and an `action` (e.g., `accept`, `deny`).
*   **`definitions` (aerleon.lib.naming.Naming):** This object holds the definitions for all named entities (like IP addresses, networks, services/ports) referenced in the policy.
    *   You can populate it by calling `ParseDefinitionsObject` with a dictionary structured similarly to how `NETWORK.net` and `SERVICES.svc` files are formatted, or by loading actual definition files.
    *   The `networks` key holds network definitions, and the `services` key holds service (port/protocol) definitions.

The `api.AclCheck` function processes this input and returns a summary dictionary. The `Summarize()` method (called internally by `api.AclCheck`) formats the results, indicating which terms were matched and whether the match was exact or "possible" (e.g., due to options like `tcp-established` which depend on connection state not simulated by `AclCheck`).
The output dictionary from `Summarize()` is structured as:

```json
{
    "filter_name_1": {
        "term_name_1": {
            "possibles": ["packet-length", "tcp-est"],
            "message": "  term: term_name_1 (possible match)\n    action if ['packet-length', 'tcp-est']"
        },
        "term_name_2": {
            "possibles": [],
            "message": "  term: term_name_2\n    accept"
        }
    },
}
```

To programmatically determine the outcome of specific traffic flows through your defined policies, use a process like this:

1. If only one term matched the traffic, split the 'message' field by newline and examine the final action (e.g. "accept" above).
2. If there is a conditional match, collect all distinct possible outcomes and present the conditional basis (e.g. deny if ['packet-length']).
