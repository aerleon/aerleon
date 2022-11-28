"""New-style Cisco Plug-in"""

from __future__ import annotations

import typing

from aerleon.lib import plugin

if typing.TYPE_CHECKING:
    from aerleon.lib import policy


def AerleonPlugin():
    return CiscoPlugin()


class CiscoPlugin(plugin.BasePlugin):
    def __init__(self):
        pass

    def RequestMetadata(self, _platformMetadata):
        return plugin.PluginMetadata(capabilities=[plugin.PluginCapability.GENERATOR])

    @property
    def generators(self):
        return GENERATORS


class CiscoGenerator(plugin.BaseGenerator):
    def __init__(self, target, platformMetadata):
        self.target = target
        self.platformMetadata = platformMetadata

    def getConfiguration(self):
        return plugin.GeneratorConfiguration(
            useAddressBook=False, useFlatten=False, useMutable=False
        )

    def generate(self, pol: policy.Policy):
        return "FAKE POLICY"  # TODO(jb) WIP


GENERATORS = {
    "cisco": CiscoGenerator,
    "ciscoasa": CiscoGenerator,
    "cisconx": CiscoGenerator,
    "ciscoxr": CiscoGenerator,
}
