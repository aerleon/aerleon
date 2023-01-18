![GitHub](https://img.shields.io/github/license/aerleon/aerleon) [![PyPI version](https://badge.fury.io/py/aerleon.svg)](https://badge.fury.io/py/aerleon) ![PyPI - Status](https://img.shields.io/pypi/status/aerleon)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aerleon) [![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black) ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/aerleon/aerleon/main.yml?branch=main) ![Snyk Vulnerabilities for GitHub Repo](https://img.shields.io/snyk/vulnerabilities/github/aerleon/aerleon)[![codecov](https://codecov.io/gh/aerleon/aerleon/branch/main/graph/badge.svg?token=C13SR6GMTD)](https://codecov.io/gh/aerleon/aerleon)

# Aerleon

Generate firewall configs for multiple platforms at once.

Aerleon is a fork of [Capirca](https://github.com/google/capirca) with the following enhancements:

- New platform generators can now be added as plugins. Users no longer need to fork the project to add support for new platforms. Common platform support is still built in.
- YAML is now supported for policy files, network definitions, and service definitions.
- A powerful new Generate API is added that accepts policies, network definitions, and service definitions as native Python data.
- Performance in address book generation for SRX and Palo Alto targets is greatly improved.
- A detailed regression test suite was added to the project.
- Unit and regression tests run automatically on all pull requests.
- New developer tools are integrated with the project: Poetry, PyProject, nox, Codecov, SigStore.

See the [1.0.0 Release Notes](https://github.com/aerleon/aerleon/releases/tag/1.0.0) for a complete list of changes.


## Install

Aerleon requires Python 3.7 or higher.

```bash
pip install aerleon
```

More detailed instructions can be found on the [Installation](https://aerleon.readthedocs.io/en/latest/install/) page.

### Usage

See [Getting Started](https://aerleon.readthedocs.io/en/latest/getting_started/).

## Policy Files

A policy file describes a security policy using _header_ and _term_ blocks.
Header blocks describe how to generate the output configuration of the security
policy. Term blocks define the access control rules within an ACL.

In .pol.yaml files, each ACL has exactly one header and one or more term
sections. In .pol file format, each ACL is defined by a top-level header block
followed by one or more top-level term blocks.

```yaml
acls:
  - header:
      comment:
        this is a sample policy for a zone based filter that generates multiple
        output formats. It checks logging options, tcp, udp and icmp type
        options.
      targets:
        paloalto: from-zone internal to-zone external
        srx: from-zone internal to-zone external
    terms:
      - name: test-tcp-log-both
        comment: Testing log-both for tcp.
        protocol: tcp
        logging: log-both
        action: accept
      - name: test-udp-log
        comment: Testing logging for udp.
        protocol: udp
        logging: true
        action: accept
```

See [Policy Files](https://aerleon.readthedocs.io/en/latest/getting_started/#policy-files) for full details.

## Address Book

Address book files define symbolic names for IP networks, hosts, and services.
Policy files may reference these names.

```yaml
terms:
  - name: deny-to-bad-destinations
    destination-address: RFC1918 BOGON RESERVED
    action: deny
```

```yaml
networks:
  RFC1918:
    values:
      - address: 10.0.0.0/8
        comment: "non-public"
      - address: 172.16.0.0/12
        comment: "non-public"
      - address: 192.168.0.0/16
        comment: "non-public"
  RESERVED:
    values:
      - address: 0.0.0.0/8
        comment: "reserved"
      - name: RFC1918
      - name: LOOPBACK
      # ...snipped...
  BOGON:
    values:
      - address: 0.0.0.0/8
      - address: 192.0.0.0/24
      - address: 192.0.2.0/24
      # ...snipped...
```

Users may wish to auto-generate address book files to keep them up to date. JSON
and CSV are accepted for this reason. See [Definition Files](https://aerleon.readthedocs.io/en/latest/getting_started/#definition-files) for full details.

## Advanced Usage

The `aerleon` Python package also provides a Python API. See
[Python Package](wiki/python-package.md) on the wiki.

To build from source, see
[Getting Started With Source](wiki/getting-started-source.md) on the wiki.

## Contributing

Contributions are welcome. Please review the contributing guidelines and code of
conduct for this project.

The [Getting Started With Source](wiki/getting-started-source.md) guide has
information on how to approach code changes to this project.

## Contact

Official channels for communicating issues is via [Github Issues](https://github.com/aerleon/aerleon/issues)

General discussions can be had either in [Github Discussions](https://github.com/aerleon/aerleon/discussions) or in our [Slack Server](https://aerleon.slack.com/)

### Contact Maintainers

You can always reach out to us on  [Slack](https://aerleon.slack.com/)
You many also reach out to us via e-mail

Rob Ankeny ([ankenyr@gmail.com](mailto:ankenyr@gmail.com))

Jason Benterou ([jason.benterou@gmail.com](mailto:jason.benterou@gmail.com))

## Resources

Aerleon is a fork of [Capirca](https://github.com/google/capirca).

Additional documentation:

- [aerleon.readthedocs.io](https://aerleon.readthedocs.io/en/latest/)

External links, resources and references:

- [Brief Overview (4 slides):](https://docs.google.com/present/embed?id=dhtc9k26_13cz9fphfb&autoStart=true&loop=true&size=1)
- [Nanog49; Enterprise QoS](http://www.nanog.org/meetings/nanog49/presentations/Tuesday/Chung-EnterpriseQoS-final.pdf)
- [Blog Post: Safe ACL Change through Model-based Analysis](https://tech.ebayinc.com/engineering/safe-acl-change-through-model-based-analysis/)
- [Aerleon Slack](https://aerleon.slack.com/)
- [#aerleon at NetworkToCode Slack](https://networktocode.slack.com/)

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center"><a href="https://github.com/itdependsnetworks"><img src="https://avatars.githubusercontent.com/u/9260483?v=4?s=100" width="100px;" alt="Ken Celenza"/><br /><sub><b>Ken Celenza</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=itdependsnetworks" title="Documentation">📖</a></td>
      <td align="center"><a href="https://github.com/fischa"><img src="https://avatars.githubusercontent.com/u/11302991?v=4?s=100" width="100px;" alt="Axel F"/><br /><sub><b>Axel F</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=fischa" title="Documentation">📖</a></td>
    </tr>
  </tbody>
  <tfoot>
    <tr>
      <td align="center" size="13px" colspan="7">
        <img src="https://raw.githubusercontent.com/all-contributors/all-contributors-cli/1b8533af435da9854653492b1327a23a4dbd0a10/assets/logo-small.svg">
          <a href="https://all-contributors.js.org/docs/en/bot/usage">Add your contributions</a>
        </img>
      </td>
    </tr>
  </tfoot>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## Credit

Files and code included in this project from Capirca are copyright Google and
are included under the terms of the Apache License, Version 2.0. You may obtain
a copy of the License at

  <http://www.apache.org/licenses/LICENSE-2.0>

Contributors who wish to modify files bearing a copyright notice are obligated
by the terms of the Apache License, Version 2.0 to include at the top of the
file a prominent notice stating as much. Copyright notices must not be removed
from files in this repository.

This README file may contain phrases and sections that are copyright Google.
This file is modified from the original.
