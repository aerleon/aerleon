![GitHub](https://img.shields.io/github/license/aerleon/aerleon) [![PyPI version](https://badge.fury.io/py/aerleon.svg)](https://badge.fury.io/py/aerleon) ![PyPI - Status](https://img.shields.io/pypi/status/aerleon) ![PyPI - Downloads](https://img.shields.io/pypi/dm/aerleon)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aerleon) [![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black) ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/aerleon/aerleon/main.yml?branch=main) ![Snyk Vulnerabilities for GitHub Repo](https://img.shields.io/snyk/vulnerabilities/github/aerleon/aerleon)[![codecov](https://codecov.io/gh/aerleon/aerleon/branch/main/graph/badge.svg?token=C13SR6GMTD)](https://codecov.io/gh/aerleon/aerleon)

# Aerleon

Generate firewall configs for multiple platforms at once.

Aerleon is a fork of [Capirca](https://github.com/google/capirca) with the following enhancements:

- Support for new firewall platforms can be added through plugins. Plugins for
  common platforms are built-in. Users with experimental or non-public platforms
  can add support without forking this repo.
- YAML support for Policy, Network, and Services.
- Performance is generally faster.
- A well-documented Python API is provided which accepts native types.
- A cleaner test harness is provided for end-to-end tests.
- "Shade checking" is faster and more correct.

## Install

Aerleon requires Python 3.7 or higher.

```bash
pip install aerleon
```

More instructions on installation can be found [here](link to readme)

## Documentation
Documentation can be found at [aerleon.readme.io] where we cover many topics.

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
