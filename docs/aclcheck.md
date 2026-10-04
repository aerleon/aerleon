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
*   `-d, --destination IP`: Destination IP address or network. Defaults to `200.1.1.1`.
*   `-s, --source IP`: Source IP address or network. Defaults to `any`.
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
         --destination 172.16.1.0/24 \
         --protocol udp \
         --dport 53 \
         --sport 12345
```

This command will check the `sample_cisco_lab.yaml` policy, using definitions from the `./def` directory, for traffic from `10.1.1.1` (source port `12345`) to `172.16.1.0/24` (destination port `53`) using the UDP protocol. The output will indicate which terms in the policy match this traffic and what action or actions are taken.

## API Usage

Aerleon includes a Python interface for `AclCheck`, allowing for programmatic integration into other tools or automation workflows.

See the separate `AclCheck` API documentation for more details.
