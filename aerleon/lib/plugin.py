"""Aerleon Plug-in Interface.

Aerleon operates through an extensible plug-in framework. Some plug-ins are
included by default with no action or configuration required by the user in
order to use them. Additional plug-ins can be downloaded from PyPI or Github,
both official plug-ins provided by the Aerleon project as well as third-party
or self-authored plug-ins.

At the time of writing only one plug-in type is supported, Generator, which
generates configs for a firewall platform. Future work may add support for
extensible Naming and front-end through the plug-in system.

The primary process by which Users can add plug-ins makes use of Python's
built-in plug-in discovery tools. In this model, the current Python will search
for installed packages with a plug-in entrypoint matching "aerleon.plugin".

In setuptools this would look like:

```
setup(
    ...
    entry_points={'aerleon.plugins': 'cisco = cisco:AerleonPlugin'},
    ...
)
```

In poetry this would look like:

```
[tool.poetry.plugins."aerleon.plugin"]
export = "cisco:AerleonPlugin"
```

Install plug-ins by using 'pip install <package>' in the same Python installation
or (virtual environment) in which you installed Aerleon. `pipx` users will need to
use the `pipx inject` command, e.g.

```
pipx inject aerleon aerleon-cisco
```

See also:

https://setuptools.pypa.io/en/latest/userguide/entry_point.html#entry-points-for-plugins
https://python-poetry.org/docs/pyproject/#plugins


# Classes

## BasePlugin

All Aerleon plug-ins must extend aerleon.plugin.BasePlugin and implement the
required methods __init__() and RequestMetadata(). RequestMetadata() must return
an instance of aerleon.plugin.PluginMetadata or raise
aerleon.plugin.PluginCompatibilityError .

Plug-ins that include aerleon.plugin.PluginType.GENERATOR under 'capabilities'
must implement the property .generators and return a dictionary
mapping target names to class constructors.

These generator classes must implement BaseGenerator and implement the required
methods __init__() and Generate().

"""

from __future__ import annotations

import typing
from dataclasses import dataclass
from enum import Enum

if typing.TYPE_CHECKING:
    from aerleon.lib import aclgenerator


class PluginCompatibilityError(BaseException):
    """A plugin should raise this exception in its implementation of requestMetadata()
    if this plug-in is not compatible with the current Aerleon version."""


class PluginCapability(Enum):
    """Type of functionality offered by a plugin."""

    GENERATOR = 1


@dataclass
class PluginMetadata:
    """General metadata about the current plugin.

    Attributes:
        capabilities: The type(s) of functionality provided by this plugin."""

    capabilities: set[PluginCapability]


class BasePlugin:
    def __init__(self):
        raise NotImplementedError

    def RequestMetadata(self, _platformMetadata: SystemMetadata) -> PluginMetadata:
        """
        Arguments:
            platformMetadata: A dict containing metadata about the running version of Aerleon.

        Returns:
            A PluginMetadata object containing general metadata about the current plugin.

        Raises:
            PluginCompatibilityError: If this plugin requires a different version of Aerleon."""
        raise NotImplementedError

    @property
    def generators(self) -> dict[str, type[aclgenerator.ACLGenerator]]:
        raise NotImplementedError


@dataclass
class SystemMetadata:
    """Interface for the engine to provide metadata about itself to plugins."""

    engine_version: str
