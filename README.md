![GitHub](https://img.shields.io/github/license/aerleon/aerleon) [![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)
[![PyPI version](https://badge.fury.io/py/aerleon.svg)](https://badge.fury.io/py/aerleon) ![PyPI - Status](https://img.shields.io/pypi/status/aerleon) ![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aerleon) ![PyPI - Downloads](https://img.shields.io/pypi/dm/aerleon)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/aerleon/aerleon/release.yml) ![Snyk Vulnerabilities for GitHub Repo](https://img.shields.io/snyk/vulnerabilities/github/aerleon/aerleon) [![aerleon](https://snyk.io/advisor/python/aerleon/badge.svg)](https://snyk.io/advisor/python/aerleon) [![codecov](https://codecov.io/gh/aerleon/aerleon/branch/main/graph/badge.svg?token=C13SR6GMTD)](https://codecov.io/gh/aerleon/aerleon)

# Aerleon

Generate firewall configs for multiple firewall platforms from a single platform-agnostic configuration language through a command line tool and Python API.

Aerleon is a fork of [Capirca](https://github.com/google/capirca) with the following major additions:
- YAML policy and network definition files and [pol2yaml, a converter from Capirca policy DSL to YAML](https://github.com/aerleon/pol2yaml).
- Network definitions with FQDN data.
- New firewall platforms can be added through plugins.
- Typed Python APIs for ACL generation and aclcheck queries.
- A [SLSA-compatible verifiable release process](https://aerleon.readthedocs.io/en/latest/install/#verifying-installation).
- A detailed regression test suite.
- Many bug fixes and performance enhancements.

### Prerequisites
Aerleon requires Python 3.9 or higher.

### Installation Steps
You can install Aerleon using one of the following package managers:

#### Option 1: pip (Python Package Index)
Install Aerleon using `pip`:
```bash
pip install aerleon
```

#### Option 2: Homebrew (macOS/Linux)
Install Aerleon using Homebrew:
```bash
brew install aerleon
```

### Overview
Aerleon provides a command line tool and a Python API to generate configs for multiple firewall platforms from a single platform-agnostic configuration language. Supported platforms include Cisco, Juniper, Palo Alto Networks, and [many others](https://aerleon.readthedocs.io/en/latest/#core-supported-generators).

A [getting started guide](https://aerleon.readthedocs.io/en/latest/getting_started/) is available to walk through the basics of using Aerleon.

### Documentation
Full documentation can be found at [https://aerleon.readthedocs.io/en/latest/](https://aerleon.readthedocs.io/en/latest/).

### Contributing
Contributions are welcome. Please review the [contributing guidelines](https://aerleon.readthedocs.io/en/latest/contributing/) and [code of conduct](https://github.com/aerleon/aerleon/blob/main/CODE_OF_CONDUCT.md).

### Contact
#### Official Communication Channels
- Issues: [GitHub Issues](https://github.com/aerleon/aerleon/issues).
- Discussions: [GitHub Discussions](https://github.com/aerleon/aerleon/discussions).
- Community Chat: [Slack Server](https://join.slack.com/t/aerleon/shared_invite/zt-1ngckm6oj-cK7yj63A~JgqjixEui2Vhw).

#### Maintainers
- Rob Ankeny ([ankenyr@gmail.com](mailto:ankenyr@gmail.com))
- Jason Benterou ([jason.benterou@gmail.com](mailto:jason.benterou@gmail.com))

### Version History
Refer to the [changelog](https://github.com/aerleon/aerleon/releases) for version updates.

### Resources
- [Getting Started Guide](https://aerleon.readthedocs.io/en/latest/getting_started/)
- [Blog Post: Safe ACL Change through Model-based Analysis](https://tech.ebayinc.com/engineering/safe-acl-change-through-model-based-analysis/)
- [Aerleon Slack](https://join.slack.com/t/aerleon/shared_invite/zt-1ngckm6oj-cK7yj63A~JgqjixEui2Vhw)

### Credits
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
## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/itdependsnetworks"><img src="https://avatars.githubusercontent.com/u/9260483?v=4?s=100" width="100px;" alt="Ken Celenza"/><br /><sub><b>Ken Celenza</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=itdependsnetworks" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/fischa"><img src="https://avatars.githubusercontent.com/u/11302991?v=4?s=100" width="100px;" alt="Axel F"/><br /><sub><b>Axel F</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=fischa" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://hachyderm.io/@nemith"><img src="https://avatars.githubusercontent.com/u/349360?v=4?s=100" width="100px;" alt="Brandon Bennett"/><br /><sub><b>Brandon Bennett</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=nemith" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/btriller"><img src="https://avatars.githubusercontent.com/u/851727?v=4?s=100" width="100px;" alt="Bastian Triller"/><br /><sub><b>Bastian Triller</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=btriller" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/XioNoX"><img src="https://avatars.githubusercontent.com/u/688817?v=4?s=100" width="100px;" alt="Arzhel Younsi"/><br /><sub><b>Arzhel Younsi</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=XioNoX" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ProtonBruno"><img src="https://avatars.githubusercontent.com/u/105855897?v=4?s=100" width="100px;" alt="ProtonBruno"/><br /><sub><b>ProtonBruno</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=ProtonBruno" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/loulecrivain"><img src="https://avatars.githubusercontent.com/u/43913579?v=4?s=100" width="100px;" alt="Lou Lecrivain"/><br /><sub><b>Lou Lecrivain</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=loulecrivain" title="Code">💻</a> <a href="https://github.com/aerleon/aerleon/commits?author=loulecrivain" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ABruihler"><img src="https://avatars.githubusercontent.com/u/6530276?v=4?s=100" width="100px;" alt="ABruihler"/><br /><sub><b>ABruihler</b></sub></a><br /><a href="https://github.com/aerleon/aerleon/commits?author=ABruihler" title="Code">💻</a> <a href="https://github.com/aerleon/aerleon/commits?author=ABruihler" title="Documentation">📖</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
