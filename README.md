![GitHub](https://img.shields.io/github/license/aerleon/aerleon) [![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)
[![PyPI version](https://badge.fury.io/py/aerleon.svg)](https://badge.fury.io/py/aerleon) ![PyPI - Status](https://img.shields.io/pypi/status/aerleon) ![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aerleon) ![PyPI - Downloads](https://img.shields.io/pypi/dm/aerleon)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/aerleon/aerleon/release.yml) ![Snyk Vulnerabilities for GitHub Repo](https://img.shields.io/snyk/vulnerabilities/github/aerleon/aerleon) [![aerleon](https://snyk.io/advisor/python/aerleon/badge.svg)](https://snyk.io/advisor/python/aerleon) [![codecov](https://codecov.io/gh/aerleon/aerleon/branch/main/graph/badge.svg?token=C13SR6GMTD)](https://codecov.io/gh/aerleon/aerleon)

# Aerleon

Generate firewall configs for multiple firewall platforms from a single platform-agnostic configuration language through a command line tool and Python API.

Aerleon is a fork of [Capirca](https://github.com/google/capirca) with the following enhancements:

- New platform generators can now be added as plugins. Users no longer need to fork the project to add support for new platforms. Common platform support is still built in.
- YAML is now supported for policy files, network definitions, and service definitions.
- A powerful new Generate API is added that accepts policies, network definitions, and service definitions as native Python data.
- Performance in address book generation for SRX and Palo Alto targets is greatly improved.
- A detailed regression test suite was added to the project.
- Unit and regression tests run automatically on all pull requests.
- New developer tools are integrated with the project: Poetry, PyProject, nox, Codecov, Sigstore.

See the [1.0.1 Release Notes](https://github.com/aerleon/aerleon/releases/tag/1.0.1) for a complete list of changes.

## Install

Aerleon requires Python 3.7 or higher.

```bash
pip install aerleon
```

## Overview

Aerleon provides a command line tool and a Python API that will generate configs for multiple firewall platforms from a single platform-agnostic configuration language. It can generate configs for Cisco, Juniper, Palo Alto Networks and [many other firewall vendors](https://aerleon.readthedocs.io/en/latest/#core-supported-generators).

A [getting started guide](https://aerleon.readthedocs.io/en/latest/getting_started/) walking through the basics of using Aerleon is available on the docs website.

## Documentation

Documentation can be found at [https://aerleon.readthedocs.io/en/latest/](https://aerleon.readthedocs.io/en/latest/).

## Contributing

Contributions are welcome. Please review the [contributing guidelines](https://aerleon.readthedocs.io/en/latest/contributing/) and [code of conduct](https://github.com/aerleon/aerleon/blob/main/CODE_OF_CONDUCT.md) for this project.

## Contact

Official channels for communicating issues is via [Github Issues](https://github.com/aerleon/aerleon/issues).

General discussions can be had either in [Github Discussions](https://github.com/aerleon/aerleon/discussions) or in our [Slack Server](https://join.slack.com/t/aerleon/shared_invite/zt-1ngckm6oj-cK7yj63A~JgqjixEui2Vhw).

### Contact Maintainers

You can always reach out to us on  [Slack](https://join.slack.com/t/aerleon/shared_invite/zt-1ngckm6oj-cK7yj63A~JgqjixEui2Vhw).
You many also reach out to us via e-mail.

Rob Ankeny ([ankenyr@gmail.com](mailto:ankenyr@gmail.com))

Jason Benterou ([jason.benterou@gmail.com](mailto:jason.benterou@gmail.com))

## Resources

- [Brief Overview (4 slides):](https://docs.google.com/present/embed?id=dhtc9k26_13cz9fphfb&autoStart=true&loop=true&size=1)
- [Nanog49; Enterprise QoS](http://www.nanog.org/meetings/nanog49/presentations/Tuesday/Chung-EnterpriseQoS-final.pdf)
- [Blog Post: Safe ACL Change through Model-based Analysis](https://tech.ebayinc.com/engineering/safe-acl-change-through-model-based-analysis/)
- [Aerleon Slack](https://join.slack.com/t/aerleon/shared_invite/zt-1ngckm6oj-cK7yj63A~JgqjixEui2Vhw)

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

This README file and other documentation files may contain phrases and sections that are copyright Google.
This file and other documentation files are modified from the original by the Aerleon Project Team.
