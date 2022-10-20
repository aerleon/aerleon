"""New-style Cisco Plug-in"""


from aerleon.lib import models, plugin


def AerleonPlugin():
    return CiscoPlugin()


class CiscoPlugin(plugin.BasePlugin):
    def __init__(self):
        pass

    def requestMetadata(self, _platformMetadata):
        return plugin.PluginMetadata(capabilities=[plugin.PluginType.GENERATOR])

    @property
    def generatorTable(self):
        return GENERATOR_TABLE


class CiscoGenerator(plugin.BaseGenerator):
    def __init__(self, target, platformMetadata):
        self.target = target
        self.platformMetadata = platformMetadata

    def getConfiguration(self):
        return plugin.GeneratorConfiguration(
            useAddressBook=False, useFlatten=False, useMutable=False
        )

    def generate(self, policy: models.Policy):
        return "FAKE POLICY"  # TODO(jb) WIP


GENERATOR_TABLE = {
    "cisco": CiscoGenerator,
    "ciscoasa": CiscoGenerator,
    "cisconx": CiscoGenerator,
    "ciscoxr": CiscoGenerator,
}
