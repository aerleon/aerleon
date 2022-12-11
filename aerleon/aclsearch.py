"""Search local policy and address book files.

Usage: `aclsearch [subcommand] [options]`

Subcommands:

    aclsearch ips <ip>...               List any networks that contain any of the given IP addresses.
    aclsearch ips <ip>... -t <network>  Report whether <ip> is contained in <network> for each IP address.
    aclsearch port <port> <protocol>    List any service definitions containing the given port and protocol.
    aclsearch compare -t <net1> <net2>  Compare two networks.
    aclsearch compare -i <ip1> <ip2>    Compare the networks to which two IP addresses belong.
    aclsearch show -t <network>...      List all IP addresses contained in each network.
    aclsearch show -s <service>...      List all port-protocol pairs contained in each service definition.
    aclsearch check []

* FIND NETWORK(S)

* FIND SERVICE DEFINITIONS(S)

* COMPARE NETWORKS

* List all IPs for a network (-o)

* List all port / protocol pairs for a service (-s)

* Search for networks or services:

* --ip / -i: Search for network definitions containing IP(s).
  * --token / -t: Restrict search to network definitions with these names.

Context: `aclsearch` provides similar capabilities to Capirca's built-in
`cgrep` and `aclcheck` tools in a single executable.
"""

def main(options):
    pass


def EntryPoint(argv):
    """Read argv"""
    main(options)


if __name__ == '__main__':
    EntryPoint()
