from collections import defaultdict
import ipaddress
import pathlib
import re
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

    INTERNAL_FIELDS = frozenset(
        [
            'translated',
            'inactive',
            'flattened',
            'flattened_addr',
            'flattened_saddr',
            'flattened_daddr',
            'stateless_reply',
        ]
    )

    def _ExportHeader(header):
        """Export a filter header to a dict."""
        header = vars(header)

        targets = {}
        for target in header['target']:
            targets[target.platform] = " ".join(target.options)
        header['target'] = targets

        objects = {}
        if header['comment']:
            objects['comment'] = '\n'.join(header['comment'])
        for keyword, value in header.items():
            if not value:
                continue

            if keyword == 'comment':
                continue

            if isinstance(value, list) and len(value) == 1:
                value = value[0]

            objects[keyword] = value

        return objects

    def _RestoreValue(obj):
        if isinstance(obj, ipaddress._IPAddressBase):
            return obj.parent_token
        elif isinstance(obj, policy.VarType):
            return obj.value
        elif isinstance(obj, list):
            return [_RestoreValue(item) for item in obj]
        else:
            return obj

    def _ExportTerm(term: policy.Term):
        """Export a term to a dict."""

        # Restore includes that were set aside
        if term.name and term.name in include_placeholders:
            include_path = term.comment[1]
            include_path = pathlib.Path(include_path).with_suffix('.yaml')
            return {'include': str(include_path)}

        objects = {'name': term.name}

        if term.comment:
            objects['comment'] = '\n'.join(term.comment)

        # Restore Nacaddr objects to their token representation
        # Remove internal fields
        # Remove fields with default values
        for keyword, value in vars(term).items():
            if keyword in INTERNAL_FIELDS:
                continue
            if keyword == 'name' or keyword == 'comment':
                continue
            if not value:
                continue

            value = _RestoreValue(value)

            if keyword == 'flexible_match_range':
                value = {item[0]: item[1] for item in value}

            if keyword == 'logging':
                platform_values = []
                for item in value:
                    if item == 'true' or item == 'True':
                        platform_values.append(True)
                    elif item == 'false' or item == 'False':
                        platform_values.append(False)
                    else:
                        platform_values.append(item)
                value = platform_values

            if keyword == 'target_resources':
                value = [f'({item[0]},{item[1]})' for item in value]

            if keyword == 'verbatim':
                platform_values = defaultdict(list)
                for item in value:
                    platform_values[item[0]].append(item[1])

                new_value = {}
                for key, value in platform_values.items():
                    new_value[key] = '\n'.join(value)

                value = new_value

            if keyword == 'vpn':
                new_value = {'name': value[0]}
                if value[1]:
                    new_value['policy'] = value[1]

            # Assuming all lists can be safely collapsed at this point
            if isinstance(value, list) and len(value) == 1:
                value = value[0]

            # Assuming every data model property name matches the YAML name
            keyword = re.sub(r'_', '-', keyword)
            objects[keyword] = value

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

    def str_presenter(dumper, data):
        """configures yaml for dumping multiline strings
        Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data"""
        if len(data.splitlines()) > 1:  # check for multiline string
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    print(yaml.safe_dump(data, sort_keys=False))  # We want term.name at the top of each term

    return yaml.safe_dump(data, sort_keys=False)


def ExportNaming(defs, style: ExportStyleRules = None):
    """Exporter for naming.Naming"""


class ExportHelperNamingImpl(naming.Naming):
    """A fake implementation of naming.Naming used in the export process.

    Normally the process of parsing a Policy file will fail if a name in that
    file is not found in the provided Naming dictionary. During the export process
    this is not a desirable behavior, so ExportHelperNamingImpl can be"""

    def __init__(self):
        pass

    def GetNetAddr(self, value):
        return [value]

    def GetServiceByProto(self, port, proto):
        return [port, proto]
