import enum
import yaml


class ExportFormat(enum.Enum):
    YAML_POLICY = enum.auto()
    YAML_INCLUDE = enum.auto()


class ExportStyleRules:
    """These rules enable stylistic variants available in the exporter."""


def ExportPolicy(pol, format: ExportFormat, style: ExportStyleRules = None):

    if not format:
        format = ExportFormat.YAML_POLICY

    if not style:
        style = ExportStyleRules()

    return yaml.dump(pol)


def _TermToDict(term):
    return vars(term)


def ExportNaming(defs, style: ExportStyleRules = None):
    """Exporter for naming.Naming"""


class ExportHelperNamingImpl:
    """A fake implementation of naming.Naming used in the export process.
    
    Normally the process of parsing a Policy file will fail if a name in that
    file is not found in the provided Naming dictionary. During the export process
    this is not a desirable behavior: """
