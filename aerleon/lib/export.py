import ipaddress
import pathlib
import re
from collections import defaultdict

import yaml

from aerleon.lib import naming, policy, policy_builder


class ExportStyleRules:
    """These rules enable stylistic variants available in the exporter.

    At this moment there are none. Best if we can keep it this way!"""


# Notes on reconstruction from PolicyParseData / HeaderParseData / TermParseData
#
# 1. General Structure
# 2. Dealing With Comments
# 3. Reconstructing AddObject Calls
#
#
# ## 1. General Structure
#
# PolicyParseData represents a single policy file, composed of one or more header/termlist pairs.
# It may have an end of file comment.
#
# * The header is always a HeaderParseData
# * The termlist is a list of TermParseData
#
# A comment appearing above a header block is attached to that block.
# A comment appearing above a term block is attached to that block.
# A comment appearing at the end of a file is the end of file comment.
#
# HeaderParseData represents the header for a single filter, composed of one or more field lines.
# It may have a block comment above it.
# A field line may itself be a block comment.
# A field line may have an end of line comment.
#
# TermParseData represents a term in the filter term list, composed of a name and one or more field lines.
# It may have a block comment above it.
# A field line may itself be a block comment.
# A field line may have an end of line comment.
#
# Field lines represent a line of the form "keyword :: value_expr* line_comment".
# A field line is composed of a VarType / comment(string) pair. The comment may be None.
# In some fields the first part of the pair is a list of VarType objects.
#
#
# ## 2. Dealing With Comments
#
# Comment parsing is a new concept added for the pol2yaml change. The comment parsing scheme
# used here is not totally ideal and may have some weirdness that might need further
# changes.
#
# Each comment has an attachment to some other object that we will try to preserve in output.
# Practical comment attachment is inherently ambiguous - authors have not actually created a
# formal linkage - so some placement choices in the output are designed to be reasonable
# and in some cases maintain ambiguity.
#
# Unlike .pol, YAML files cannot have comments on the same line as a multiline string.
# The policy YAML format does not support grouping clusters of values on the same line:
# all values must be on one line or splayed out one per line.
#
# A term in .pol may have dead (overshadowed) fields that will be lost. Comments
# attached to a dead field should re-attach to the last occurence of that value.
# (Note this should raise a warning or maybe an error).
#
# The policy YAML format does not allow the same key to appear twice. This means
# values will be grouped into a single key-value expression in YAML. This grouping
# must happen in an upwards direction to maintain attachment to the top of the block.
#
# As a general rule, fields should not be sorted in blocks that contain interior comments.
# This includes line comments and field comments.
#
#
# ### Pol File Comment Placement Names
#
#
#
# # (1a) Header Block Comment (top of file)
# header {
# # (2a) Field Comment (above first field)
#   target: cisco # (3) Line Comment
# # (2b) Field Comment
#   target: srx   # (3) Line Comment
# # (2c) Field Comment (end)
# }
# # (4) Term Block Comment
# term term-1 {
#   ... same structure as header block
# }
# # (5) End Of File Block Comment
#
# Note that additional instances of Header Block Comment would be (1b) - not top of file.
#
#
#
#
# ### Inc File Comment Placement Names
#
#
#
# # (4a) Term Block Comment (top of file)
# term {
#   ... same structure as header block
# }
# # (5) End Of File Block Comment
#
# ### YAML File Comment Placement Names
#
# # (1a) Header Block Comment (top of file)
# filters:
# - header:
#     # (2a) Field Comment (above first field)
#     target:
#       cisco:  # (3) Line Comment
#     # (2b) Field Comment
#       srx:    # (3) Line Comment
#     # (2c) Field Comment (end)
#   terms:
#     # (4) Term Block Comment
#   - name: term-1
#     # (2a) Field Comment (above first field)
#     source-address:
#     - NETWORK_NAME   # (3) Line Comment
#     # (2b) Field Comment
#     - NETWORK_NAME_B # (3) Line Comment
#     # (2b) Field Comment
#     action: deny                   # (3) Line Comment
#     # (2c) Field Comment (end)
# # (5) End Of File Block Comment
#
#
#
#
# ### Comment Attachment Rules
#
# 1. Line and Field comments are attached to values, not keywords.
#    For field line with multiple values, atachment is to the first value.
# 2. Keywords must not be sorted in a Header or Term block where a 2a comment
#    is present (Field Comment (above first field)).
#    * Possibly better to not sort at all when 2/3 comments are present.
# 3. Keywords should appear in YAML in the order they first appear in the header
#   or term block in .pol.
# 4. Comments associated with dead values should attach to the overriding value.
# 5. Line comments associated with part of a multiline string should be treated
#    as if they were field comments that appear after all actual field comments.
#
#
# ## 3. Reconstructing AddObject Calls
#
# Normally each field line will be passed to Term.AddObject or Header.AddObject, where
# some processing of the input would occur. For export we just need to convert the input.
# However there is quite a bit of field-by-field variation: similar fields may
# be structured differently within the field line, and YAML has its own rules for each field.
#
# #### Field Line / Data Model Structure
#
# Each field has a final representation in the data model:
#
# R1. Single. Additional field lines overwrite the value.
# R2. Additive. Additional field lines extend the list.
#
# Each field has a calling convention (how the data is passed to AddObject):
#
# C1. Single value: field line contains one value.
# C2. Single list : field line contains one VarType object containing a list of values.
# C3. Multiple list: field line contains a list of VarType objects.
#
# We can start to label each field.
# Not all combinations are represented. All C3 fields are R2.
# All R1 fields are C1 or C2, although the distinction isn't important yet.
# Some R2 fields are C1 or C2. So the total possibilities are:
# R1, C3, R2+C1, R2+C2
#
# VarType.SADDRESS: C3
# VarType.RESTRICT_ADDRESS_FAMILY: R1
# VarType.COMMENT: R2+C1
# VarType.FORWARDING_CLASS: R2+C1
# VarType.ICMP_TYPE: R2+C2
# VarType.ICMP_CODE: R2+C2
#
# All data in field lines are still strings. Some field data must be parseable as python integers.
#
#
# #### Preparing data for YAML
#
# 1. Classify comments and attach them to values.
# 2. Process each line into its data model.
# 3a. Normalize each field according to export normalization rules.
# 3b. Construct the export data model understood by our YAML library.
#
# On a practical basis this looks like:
# - Each k/v goes through a couple phases:
#   1. Comment-value attachment
#      Maybe tag special comments (top) if not apparent from placement
#   2. Group values by var_type. Collect values into the topmost position and move
#      comments according to comment rules. Collapse / overwrite data.
#      Tail comment / solo comment may be present but all other comments are value linked.
#   3. Construct pre-YAML data structure. Comment final placement, normalization, list
#      collapsing all happen here.
#
def ExportPolicy(pol_copy: policy.PolicyParseData, style: ExportStyleRules = None):
    if not style:
        style = ExportStyleRules()

    # Phase 1 - scan comments
    from pprint import pprint

    for data in pol_copy.data:
        print('filter:')
        print(str(data[0]))
        print('terms:')
        for termish in data[1]:
            if isinstance(termish, policy.TermParseData):
                print(f"term   : {str(termish)}")
            else:
                print(f"       : {str(termish)}")

    return

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

    UNCOLLAPSIBLE_FIELDS = frozenset(['target_resources'])

    is_include = pol_copy.is_include
    include_placeholders = pol_copy.include_placeholders

    def _ExportHeader(header: policy.HeaderParseData):
        """Export a filter header to a dict."""
        targets = {}
        var_data = defaultdict(list)

        for item in header.data:
            if isinstance(item, policy.Target):
                targets[item.platform] = " ".join(item.options)

            elif isinstance(item, policy.VarType):
                var_data[item.var_type].append(item)

            elif isinstance(item, list):
                var_data[item[0].var_type].extend(item)

            elif isinstance(item, str):
                print('============= BLOCK COMMENT ========')

        result_header = {}
        result_header['targets'] = targets
        if var_data[policy.VarType.COMMENT]:
            result_header['comment'] = '\n'.join(var_data[policy.VarType.COMMENT])
            del var_data[policy.VarType.COMMENT]

        for keyname, conf in policy_builder._Builtin.BUILTINS.items():
            call_convention, var_type = conf
            values = var_data.get(var_type, None)

            if not values:
                continue

            if not call_convention:
                continue

            if call_convention == policy_builder._CallType.SingleValue:
                result_header[keyname] = str(values[0])

            elif (
                call_convention == policy_builder._CallType.SingleList
                or call_convention == policy_builder._CallType.MultiCall
            ):
                if len(values) == 1:
                    result_header[keyname] = str(values[0])
                else:
                    result_header[keyname] = [str(value) for value in values]
        return result_header

    def _RestoreValue(obj):
        if isinstance(obj, ipaddress._IPAddressBase):
            return obj.parent_token
        elif isinstance(obj, policy.VarType):
            return obj.value
        elif isinstance(obj, list):
            return [_RestoreValue(item) for item in obj]
        else:
            return obj

    def _ExportTerm(termish: policy.TermParseData):
        """Export a term to a dict."""

        # Restore includes that were set aside
        if termish.name and termish.name in include_placeholders:
            include_path = termish.comment[1]
            include_path = pathlib.Path(include_path).with_suffix('.yaml')
            return {'include': str(include_path)}

        var_data = defaultdict(list)

        for item in termish.data:
            if isinstance(item, policy.VarType):
                var_data[item.var_type].append(str(item))

            elif isinstance(item, str):
                print('============= BLOCK COMMENT ========')

        result_term = {}
        result_term['name'] = termish.name
        if var_data[policy.VarType.COMMENT]:
            result_term['comment'] = '\n'.join(var_data[policy.VarType.COMMENT])
            del var_data[policy.VarType.COMMENT]

        if var_data[policy.VarType.FLEXIBLE_MATCH_RANGE]:
            result_term['flexible-match-range'] = {
                item[0]: item[1] for item in var_data[policy.VarType.FLEXIBLE_MATCH_RANGE]
            }
            del var_data[policy.VarType.FLEXIBLE_MATCH_RANGE]

        for keyname, conf in policy_builder._Builtin.BUILTINS.items():
            call_convention, var_type = conf
            values = var_data.get(var_type, None)

            if not values:
                continue

            if not call_convention:
                continue

            if call_convention == policy_builder._CallType.SingleValue:
                result_term[keyname] = str(values[0])

            elif (
                call_convention == policy_builder._CallType.SingleList
                or call_convention == policy_builder._CallType.MultiCall
            ):
                if len(values) == 1:
                    result_term[keyname] = str(values[0])
                else:
                    result_term[keyname] = [str(value) for value in values]
        # return result_term

        objects = {'name': termish.name}

        if termish.comment:
            objects['comment'] = '\n'.join(termish.comment)

        # Restore Nacaddr objects to their token representation
        # Remove internal fields
        # Remove fields with default values
        for keyword, value in vars(termish).items():
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

            if keyword == 'source_address_exclude':
                keyword = 'source-exclude'

            if keyword == 'destination_address_exclude':
                keyword = 'destination-exclude'

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
            if isinstance(value, list) and len(value) == 1 and keyword not in UNCOLLAPSIBLE_FIELDS:
                value = value[0]

            # Assuming every data model property name matches the YAML name
            keyword = re.sub(r'_', '-', keyword)
            objects[keyword] = value

        return objects

    data = {'filters': []}

    for item in pol_copy.data:
        if isinstance(item, tuple):
            header = _ExportHeader(item[0])
            terms = [_ExportTerm(termish) for termish in item[1]]
            data['filters'].append({'header': header, 'terms': terms})
        else:
            # Block Comment
            data['filters'].append({'block_comment': item.value})

    # In the 'include' scenario we can strip the temporary policy wrapper that allowed us to parse the file
    if is_include:
        data = {'terms': data['filters'][0]['terms']}

    def str_presenter(dumper, data):
        """configures yaml for dumping multiline strings
        Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data"""
        if len(data.splitlines()) > 1:  # check for multiline string
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    return yaml.safe_dump(data, sort_keys=False)  # We want term.name at the top of each term


def ExportNaming(defs, style: ExportStyleRules = None):
    """Exporter for naming.Naming"""

    line = line.strip()
    # TODO - break out the comment case and preserve block comment lines
    if not line or line.startswith('#'):  # Skip comments and blanks.
        return
    # Let's dump some items
    for unit in defs.networks:
        if line.find('#') > -1:  # if there is a comment, save it
            (line, comment) = line.split('#', 1)


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
