"""New-style Cisco plugin"""


from aerleon.lib import plugin


class CiscoPlugin(plugin.BasePlugin):
    def __init__(self):
        pass

    def requestMetadata(self):
        return plugin.PluginMetadata()

    @property
    def generatorTable(self):
        return GENERATOR_TABLE


class CiscoGeneratorHandle(plugin.BaseGeneratorHandle):
    def __init__(self):
        pass

    def getConfiguration(self):
        return plugin.GeneratorConfiguration(
            useAddressBook=False, useFlatten=False, useMutable=False
        )


GENERATOR_TABLE = [CiscoGeneratorHandle]


class CiscoGenerator:
    pass
