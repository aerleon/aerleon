import ipaddress
from aerleon.lib import naming, policy
import yaml


# def preprocess_yaml_term_includes(data):
#     """Modify the dictionary representation of a YAML policy file to replace
#     include statements with placeholders."""
#     for policy_filter in data["filters"]:
#         if 'terms' in policy_filter:
#             for i, term in enumerate(policy_filter['terms']):
#                 if 'include' in term:
#                     include_file = term['include']
#                     include_file_slug = re.sub(include_file, "-", '[^A-Z]')
#                     policy_filter['terms'][i] = {
#                         "name": f"ZZZZZZ-INCLUDE-PLACEHOLDER-{include_file_slug}",
#                         "comment": include_file,
#                     }


# def preprocess_yaml_includes_file(data):
#     """Place the dictionary representation of a YAML term list in a dummy policy."""
#     return {"filters": [{"header": {}, "terms": data}]}


class ExportStyleRules:
    """These rules enable stylistic variants available in the exporter."""


def ExportPolicy(pol_copy: policy.PolicyCopy, style: ExportStyleRules = None):
    if not style:
        style = ExportStyleRules()

    pol = pol_copy.policy
    is_include = pol_copy.is_include
    include_placeholders = pol_copy.include_placeholders

    def _ExportHeader(header):
        """Export a filter header to a dict."""
        header = vars(header)

        return header

    def _RestoreNetworkNames(obj):
        if isinstance(obj, ipaddress._IPAddressBase):
            return obj.parent_token
        elif isinstance(obj, list):
            return [_RestoreNetworkNames(item) for item in obj]

    def _ExportTerm(term: policy.Term):
        """Export a term to a dict."""

        # Restore includes that were set aside
        if term.name and term.name in include_placeholders:
            return {'include': term.comment[1]}

        objects = vars(term)

        # Restore Nacaddr objects to their token representation
        for keyword, value in objects.items():
            objects[keyword] = _RestoreNetworkNames(value)
        return objects

    data = {'filters': []}

    for filter in pol.filters:
        header = _ExportHeader(filter[0])
        terms = [_ExportTerm(term) for term in filter[1]]
        data['filters'].append({'header': header, 'terms': terms})

    import pprint

    pprint.pprint(data)

    # In the 'include' scenario we can strip the temporary policy wrapper that allowed us to parse the file
    if is_include:
        data = data['filters'][0]['terms']

    return yaml.dump(data)


def ExportNaming(defs, style: ExportStyleRules = None):
    """Exporter for naming.Naming"""


class ExportHelperNamingImpl(naming.Naming):
    """A fake implementation of naming.Naming used in the export process.

    Normally the process of parsing a Policy file will fail if a name in that
    file is not found in the provided Naming dictionary. During the export process
    this is not a desirable behavior, so ExportHelperNamingImpl can be """

    def __init__(self):
        pass

    def GetNetAddr(self, value):
        return [value]

    def GetServiceByProto(self, port, proto):
        return [port, proto]