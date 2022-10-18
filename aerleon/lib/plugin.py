"""Plugin handle interface"""


from dataclasses import dataclass


# TODO define exception classes
class PluginCompatibilityError(BaseException):
    pass


@dataclass
class GeneratorConfiguration:
    target: str
    useAddressBook: bool
    useFlatten: bool
    useMutable: bool = False


@dataclass
class PluginMetadata:
    """TODO(jb) expand

    providesTargets: a list of target descriptors. A target descriptor can be:
    * A string with a target name, e.g. 'cisco'.
    * A string with a target name and version selector, e.g. 'cisco/^3'.
    * A tuple with a target name and a version selector, e.g. ('cisco', '^3').
    * A list containing any of the above.
    """

    providesTargets: list[str]
    use_flatten: bool
    use_mutable: bool = False


class BasePlugin:
    def __init__(self):
        raise NotImplementedError

    def requestMetadata(self):
        raise NotImplementedError

    @property
    def generatorTable(self):
        raise NotImplementedError


class BaseGeneratorHandle:
    def __init__(self):
        raise NotImplementedError

    def getConfiguration(self):
        raise NotImplementedError
