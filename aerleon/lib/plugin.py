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
required methods __init__() and requestMetadata(). requestMetadata() must return
an instance of aerleon.plugin.PluginMetadata or raise
aerleon.plugin.PluginCompatibilityError .

Plug-ins that include aerleon.plugin.PluginType.GENERATOR under 'capabilities'
must implement the property .generators and return a dictionary
mapping target names to class constructors.

These generator classes must implement BaseGenerator and implement the required
methods __init__(), .configuration and generate(). Property .configuration must
return an instance of aerleon.plugin.GeneratorConfiguration .

Generators may extend the policy file format by recognizing new keywords or
keyword values in the Terms, Header or Target sections. The optional methods
RecognizeKeyword(), RecognizeKeywordValue() and RecognizeOption() can be
implemented for this purpose. See 'Recognizing New Keywords and Values' below.


# Recognizing New Keywords and Values

A generator plug-in can extend the list of recognized keywords in a policy file
or extend the possible valid values on the right side of a key-value expression.

RecognizeKeyword(self, context) -> RecognizerKeywordResult

When Aerleon encounters an unrecognized keyword in a policy file it will invoke
RecognizeKeyword() against all active generator plug-ins (called "surveying").
Both target generators for the current filter and other generators are consulted.
Aerleon will ignore the keyword with a "Keyword Unrecognized" warning if no
active generators recognize it. Aerleon will ignore the keyword with a "Keyword
Unused" warning if one or more active generators recognizes it but none of the
target generators for the current filter do. Aerleon will halt processing the
filter with a "Security-Critical Keyword Unused" error if any active generator
has flagged this keyword as Security Critical and one or more target generator
does not recognize it.

RecognizeKeywordValue(self, context) -> RecognizerValueResult

Every value on the right side of a key-value expression is checked against
the RecognizeKeywordValue method of all target generators for the current filter.
Generators can mostly ignore this method or return None for most inputs. Any
value returned by RecognizeKeywordValue() will be installed in the 'extras'
section of the Terms, Header or Target data model.

RecognizeOption(self, context) -> RecognizerOptionResult

Special processing is performed for the 'options' keyword in a Term section.
Similar to RecognizeKeyword, Aerleon will survey all active generators in order
to determine if an option is considered Security Critical. Aerleon will halt
processing the filter with the error "Security-Critical Option Ignored" if one
or more target generators would ignore a Security Critical option.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import typing

if typing.TYPE_CHECKING:
    from aerleon.lib.recognizers import (
        RecognizerContext,
        RecognizerKeywordResult,
        RecognizerOptionResult,
        RecognizerValueResult,
    )


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

    def RequestMetadata(self, _platformMetadata: dict) -> PluginMetadata:
        """
        Arguments:
            platformMetadata: A dict containing metadata about the running version of Aerleon.

        Returns:
            A PluginMetadata object containing general metadata about the current plugin.

        Raises:
            PluginCompatibilityError: If this plugin requires a different version of Aerleon."""
        raise NotImplementedError

    @property
    def generators(self) -> dict[str, BaseGenerator]:
        raise NotImplementedError


@dataclass
class GeneratorConfiguration:
    target: str
    useAddressBook: bool
    useFlatten: bool
    useMutable: bool = False


class BaseGenerator:
    def __init__(self):
        raise NotImplementedError

    @property
    def configuration(self) -> GeneratorConfiguration:
        raise NotImplementedError

    def RecognizeKeyword(self, _context: RecognizerContext) -> RecognizerKeywordResult:
        raise NotImplementedError

    def RecognizeKeywordValue(self, _context: RecognizerContext) -> RecognizerValueResult:
        raise NotImplementedError

    def RecognizeOption(self, _context: RecognizerContext) -> RecognizerOptionResult:
        raise NotImplementedError

    def generate(self):
        raise NotImplementedError
