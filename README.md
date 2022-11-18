# Aerleon

<p align="center">
  <img src="./images/icon-aerleon.png" class="logo" height="200px">
  <br>
  <a href="https://github.com/ankben/aerleon/actions"><img src="https://github.com/ankben/aerleon/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://aerleon.readthedocs.io/en/latest"><img src="https://readthedocs.org/projects/aerleon/badge/"></a>
  <a href="https://pypi.org/project/aerleon/"><img src="https://img.shields.io/pypi/v/aerleon"></a>
  <a href="https://pypi.org/project/aerleon/"><img src="https://img.shields.io/pypi/dm/aerleon"></a>
  <br>
</p>

## Overview

Generate firewall configs for multiple platforms at once.

Aerleon is a fork of Capirca with the following enhancements:

- Support for new firewall platforms can be added through plugins. Plugins for common platforms are built-in. Users with experimental or non-public platforms can add support without forking this repo.
- Policy files can be given as YAML (.pol.yaml).
- Address Book data can be loaded from standard data formats like JSON, CSV.
- Existing .net, .svc and .pol files are still supported.
- Remote Address Book sources are supported. Users can link directly to IPAM.
- Performance is generally faster.
- A well-documented Python API is provided which accepts native types.
- A cleaner test harness is provided for end-to-end tests.
- "Shade checking" is faster and more correct.
- --help mode is much cleaner.

## Documentation

Full web-based HTML documentation for this library can be found over on the [Aerleon Docs](https://aerleon.readthedocs.io) website:

- [User Guide](https://aerleon.readthedocs.io/en/latest/user/lib_overview/) - Overview, Using the library, Getting Started.
- [Administrator Guide](https://aerleon.readthedocs.io/en/latest/admin/install/) - How to Install, Configure, Upgrade, or Uninstall the library.
- [Developer Guide](https://aerleon.readthedocs.io/en/latest/dev/contributing/) - Extending the library, Code Reference, Contribution Guide.
- [Release Notes / Changelog](https://aerleon.readthedocs.io/en/latest/admin/release_notes/).
- [Frequently Asked Questions](https://aerleon.readthedocs.io/en/latest/user/faq/).

### Contributing to the Docs

All the Markdown source for the library documentation can be found under the [docs](https://github.com/ankben/aerleon/tree/develop/docs) folder in this repository. For simple edits, a Markdown capable editor is sufficient - clone the repository and edit away.

If you need to view the fully generated documentation site, you can build it with [mkdocs](https://www.mkdocs.org/). A container hosting the docs will be started using the invoke commands (details in the [Development Environment Guide](https://aerleon.readthedocs.io/en/latest/dev/dev_environment/#docker-development-environment)) on [http://localhost:8001](http://localhost:8001). As your changes are saved, the live docs will be automatically reloaded.

Any PRs with fixes or improvements are very welcome!

## Questions

For any questions or comments, please check the [FAQ](https://aerleon.readthedocs.io/en/latest/user/faq/) first. Feel free to also swing by the [Network to Code Slack](https://networktocode.slack.com/) (channel `#aerleon`), sign up [here](http://slack.networktocode.com/) if you don't have an account.

## Credit

Files and code included in this project from Capirca are copyright Google and
are included under the terms of the Apache License, Version 2.0. You may obtain
a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Contributors who wish to modify files bearing a copyright notice are obligated
by the terms of the Apache License, Version 2.0 to include at the top of the
file a prominent notice stating as much. Copyright notices must not be removed
from files in this repository.

This README file may contain phrases and sections that are copyright Google.
This file is modified from the original.
