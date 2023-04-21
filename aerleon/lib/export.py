from enum import Enum, Flag
import enum
import io
import ipaddress
import pathlib
import re
from collections import defaultdict

from aerleon.lib import naming, policy_builder
from aerleon.lib.policy import (
    VarType,
    ValueExpr,
    Target,
    CommentExpr,
    TermParseData,
    HeaderParseData,
    PolicyParseData,
)

from ruamel.yaml import CommentedMap, CommentedSeq, YAML
from ruamel.yaml.error import CommentMark
from ruamel.yaml.tokens import CommentToken
from ruamel.yaml.scalarstring import LiteralScalarString


class ExportStyleRules:
    """These rules enable stylistic variants available in the exporter.

    At this moment there are none. Best if we can keep it this way!"""


# Notes on reconstruction from PolicyParseData / HeaderParseData / TermParseData
#
# 1. General Structure
# 2. Dealing With Comments
# 3. Reconstructing AddObject Calls
# 4. Working With Ruamel-YAML
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
# ### Comment Representation in *ParseData
#
# The parser expects comments to potentially appear anywhere in the file. This
# labelled example shows the comment positions distinguished by the parser:
#
#
# #  AAA
# #  AAA  File Block Comment
# #  AAA
# header {  # BBB Header Block Comment
#   # BBB Header Block Comment
#   target:: juniper edge-outbound  # CCC EOL Comment
#   # BBB Header Block Comment
# }  # DDD Termlist Block Comment
# # DDD Termlist Block Comment
# term deny-to-bad-destinations { # EEE Term Block Comment
#   # EEE Term Block Comment
#   destination-address:: RFC1918 BOGON RESERVED # CCC EOL Comment
#   # EEE Term Block Comment
# } # DDD Termlist Block Comment
# # DDD Termlist Block Comment
#
# Note: the parser does not distinguish comments on the same line as an opening brace from
# a comment on the next line. Users might prefer maintaining this placement.
#
# Issue: comments are not allowed in between "header {" or "term name {". Comments are not
# allowed betweeen values on a splayed out value line. Expanding on this issue:
# * .pol allows whitespace, newlines and comments essentially everywhere, including
# * Between term and term name, in the middle of double colons, in the middle of value
#   expressions...
# So a more ideal position map would consider those cases. In the following illustration,
# the ideal position map uses markers .A, .B, etc to show positions.
#
# .A: File Comment
# .B: Header/Term Key Line Comment
# .C: Block Comment
# .D: Field Key Line Comment
# .E: Value Line Comment
# .F: Value Block Comment
# .G: Term Block Comment
#
#
# #.A
# #.A
# header #.B
# #.B
# { #.B
# #.C
# target #.D
# #.D
# : #.D
# #.D
# : #.D
# #.D
# juniper #.E
# #.F
# edge-inbound #.E
# #.F
# inet #.E
# #.C
# } #.G
# #.G
# term #.B
# #.B
# deny-to-bad-destinations #.B
# #.B
# { #.B
# #.C
# destination-address #.D
# #.D
# : #.D
# #.D
# : #.D
# #.D
# RFC1918 #.E
# #.F
# BOGON #.E
# #.F
# RESERVED #.E
# #.C
# } #.G
# #.G
#
# Mapping these back to YAML, we get something like the following example. Note that the
# presence of comments may distort the formatting a little bit - we don't really want to
# preserve whitespace, splaying, etc unless it's relevant to comment placement. Also note
# that the comment indentation may not match the final version - in fact we might even want to
# detect comment alignment in the input file.
#
#
# #.A
# #.A
# filters:
# - header: #.B Fuse all key lines
#           #.B
#           #.B
# #.C
#     target: #.D Fuse all key lines
#             #.D
#             #.D
#             #.D
#             #.D
#             #.D
#       juniper: #.E This was a value EOL comment we converted to a key line
# #.F
#       - edge-inbound #.E This list could have been collapsed if not for comments
# #.F
#       - inet         #.E
# #.C
#   terms:
# #.G
#   - name: deny-to-bad-destinations #.B
#                                    #.B
#                                    #.B
#                                    #.B
#                                    #.B
#     destination-address: #.D
#                          #.D
#                          #.D
#                          #.D
#                          #.D
#                          #.D
#     - RFC1918  #.E This list also could have been collapsed if not for comments
# #.F
#     - BOGON    #.E
# #.F
#     - RESERVED #.E
# #.C
# #.G
# #.G A Term Block Comment at the very end of the file is indented as a file comment
#
# Implementation note: list collapsing should not be performed for long lists.
#
# Implementation note: because we don't really know the YAML value length (quotes may need
# to be added for 1.1), it's hard to calculate max value length across a list. But what we
# can do is render to YAML once, have Ruamel parse it, and look at the CommentToken line/char
# marks to find the max same-line comment placement in a list. Of course reading comment
# data out of Ruamel is not always straightforward!
#
# For reference, the same example as above without any comments:
#
# filters:
# - header:
#     target:
#       juniper: edge-inbound inet
#   terms:
#   - name: deny-to-bad-destinations
#     destination-address: RFC1918 BOGON RESERVED
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
# C3. Multiple objects: field line contains a list of VarType objects.
#
# We can start to label each field.
# Not all combinations appear in the code. All C3 fields are R2.
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
#      collapsing all happen here. See the next section for details of the pre-YAML structure.
#
#
# ## 4. Working With Ruamel-YAML
#
# Ruamel-YAML is a comment and anchor-aware YAML toolkit. It can load a YAML document into
# a hybrid parse tree that includes comment spans. While its main use case seems to be
# opening YAML documents, it offers (to some extent) mechanisms for directly constructing
# a hybrid parse tree which we can dump to a file. Through this process we can generate a
# YAML file with comments placed in the appropirate locations.
#
# NOTE: by default, Ruamel-YAML operates in 1.2 mode, while PyYAML only supports YAML 1.1 .
# This opens the door for some problems: some string values that must be quoted in YAML 1.1
# do not need to be quoted in 1.2, so a YAML 1.2 dumper might produce a document that will
# be misunderstood by a YAML 1.1 loader (e.g. `on: no` would load as {True: False} in YAML 1.1
# and as {"on": "no"} in YAML 1.2). It looks like we can use this to pin the output version:
#   yaml_inst = YAML()
#   yaml_inst.verion = (1, 1)
#   yaml_inst.dump(data, ...)
#
# Loading YAML can useful for yaml-to-yaml operations since we would want to preserve anchors
# and comments. At the time of writing, yaml-to-yaml is not in scope.
#
# The parts of Ruamel-YAML's data model we will use are CommentedMap and CommentedSeq.
# Ruamel-YAML also has a concept of comment placement that we need to understand in order to
# correctly place comments and understand its data model.
#
# This example YAML document is annotated with paths showing how comments are grouped and stored
# within CommentedMap / CommentedSeq. In the example, the asterisk (*) indicates that we are looking
# into the shadow comment document. The annotations are taken from Ruamel-YAML's actual parse tree.
#
# # Start Comment Line 1                (document)*.start[1]
# # Start Comment Line 2                (document)*.start[1]
#
# # Start Comment Line 4                (document)*.start[1]
# filters: # Key Comment Line 1         (document)['filters']*.start[0]
#   # Key Comment Line 2                (document)['filters']*.start[0]
#   terms: # Key Comment Line 1         (document)['filters']['terms']*.start[0]
#     # Key Comment Line 2              (document)['filters']['terms']*.start[0]
#     - item1  # Value Comment Line 1   (document)['filters']['terms']*.items[0][0]
#     # Value Comment Line 2            (document)['filters']['terms']*.items[0][0]
#     - item2  # Value Comment Line 1   (document)['filters']['terms']*.items[1][0]
#     # Value Comment Line 2            (document)['filters']['terms']*.items[1][0]
#   header:
#     target: cisco # Value Comment 1   (document)['filters']['header']*.items['target'][2]
#     # Value Comment Line 2            (document)['filters']['header']*.items['target'][2]
#
# NOTE: This example does not cover all possible comment representations in the comment
# model.
#
# The key takeaways in this example are:
# (1) Ruamel-YAML is using three types of comment placement here:
#     1. Start Comments, which appear mainly at the start of a file.
#     2. Key Comments, which appear after a key but before its contents.
#     3. EOL Comments, which appear after a value.
# (2) Comments can be contain newlines and can be multiple lines long. Although not shown
#     in this example, comments can even start with newlines, so an EOL comment can appear
#     to start on the line after.
# (3) All placement scenarios needed by this project can handled with these three placement types.
#
# When attaching comments to CommentedMap / CommentedSeq, it's important to be aware that some of
# the public comment manipulation methods accept strings, while others accept tokens (CommentToken).
# These methods accept comments as strings:
#
#   CommentedBase.yaml_set_start_comment
#   CommentedBase.yaml_set_comment_before_after_key
#   CommentedBase.yaml_add_eol_comment
#
# These methods accept comments as CommentTokens:
#
#   CommentedBase.yaml_end_comment_extend
#   CommentedBase.yaml_key_comment_extend
#   CommentedBase.yaml_value_comment_extend
#
# If possible, this exporter will try to use the three "public interface" methods to produce all
# required placements.
#
# Another note on Ruamel-YAML's three "public interface" methods: comments set through these methods
# can occlude one another. Comments in the shadow comment document can be skipped during the dumping
# process. Curiously, it appears that during the loading process, sometimes one comment is entered
# in multiple places in the shadow comment document, so as users of these interfaces we may have to
# consider that the order in which comments are visited during dumping may not make sense outside of
# the context of duplication.
#
#
# from ruamel.yaml import YAML, CommentedMap, CommentedSeq
# h1t = CommentedMap({'cisco': '', 'srx': ''})
# >>> nl11 = CommentedSeq(['NETWORK_NAME', 'NETWORK_NAME_B'])
# >>> t11 = CommentedMap({'name': 'term-1', 'source-address': nl11, 'action': 'deny'})
# >>> tlist1 = CommentedSeq([t11])
# >>> f1 = CommentedMap({'header': h1, 'terms': tlist1})
# >>> flist1 = CommentedSeq([f1])
# >>> doc = CommentedMap({'filters': flist1})
# >>> yml = YAML()
# >>> yml.version = (1,1)
# >>> import sys
# >>> yml.dump(doc, sys.stdout)
#
# doc.yaml_set_start_comment('# (1a) Header Block Comment (top of file)')
# f1.yaml_set_comment_before_after_key('header', after='(2a) Field Comment (above first field)', after_indent=4)
# h1t.yaml_add_eol_comment('# (3) Line Comment\n      # (2b) Field Comment', key='cisco')
# h1t.yaml_set_comment_before_after_key('srx', before='(2b) Field Comment', indent=6)


def CommentedSeq_yaml_set_comments(
    cs: CommentedSeq, pos: int, eol_comment: str = None, after_comment: str = None
):
    """Place a comments on a sequence value expression at the end of the line and/or following line."""
    # Ruamel's comment manipulation interface does not provide any way to place a comment
    # on the line following a list item except by directly assembling shadow comment data.
    # Per https://stackoverflow.com/questions/71710539/how-to-add-surrounding-comments-to-an-element-in-a-list
    comment_parts = []
    if eol_comment:
        comment_parts.append(f'# {eol_comment}')
    if after_comment:
        comment_parts.append(f'\n# {after_comment}')
    cs.ca.items[pos] = [CommentToken(''.join(comment_parts), CommentMark(0)), None, None, None]


def CommentedMap_yaml_set_comments(
    cm: CommentedMap, key, eol_comment: str = None, after_comment: str = None
):
    """Place a comments on a mapping value expression at the end of the line and/or following line."""
    # Ruamel's comment manipulation interface does not provide any way to place a comment
    # on the line following a list item except by directly assembling shadow comment data.
    # Per https://stackoverflow.com/questions/71710539/how-to-add-surrounding-comments-to-an-element-in-a-list
    comment_parts = []
    if eol_comment:
        comment_parts.append(f'# {eol_comment}')
    if after_comment:
        comment_parts.append(f'\n# {after_comment}')
    cm.ca.items[key] = [CommentToken(''.join(comment_parts), CommentMark(0)), None, None, None]


# def CommentedSeq_yaml_set_comment_after(cs: CommentedSeq, pos: int, comment: str):
# """Place a comment on the line following a value expression. Helper function for Ruamel-YAML."""
# Ruamel's comment manipulation interface does not provide any way to place a comment
# on the line following a list item except by directly assembling shadow comment data.
# Per https://stackoverflow.com/questions/71710539/how-to-add-surrounding-comments-to-an-element-in-a-list
# cs.ca.items[pos] = [CommentToken(f'\n{comment}', CommentMark(0)), None, None, None]


def CommentedMap_yaml_set_comment_after(cm: CommentedMap, key, comment: str):
    """Place a comment on the line following a key/value expression. Helper function for Ruamel-YAML."""
    # TODO test in pdb
    cm.ca.items[key] = [CommentToken(f'\n{comment}', CommentMark(0)), None, None, None]


def ExportPolicy(pol_copy: PolicyParseData, style: ExportStyleRules = None):
    """Export policy file parse data to YAML.

    Args:
        pol_copy: A PolicyParseData object containing an abstract representation of the contents
            of a policy file.
        style: (UNUSED) An ExportStyleRules object customizing output representation.

    Returns:
        A string containing a YAML file representation of the input policy file."""
    if not style:
        style = ExportStyleRules()

    from pprint import pprint

    yaml = YAML()
    yaml.version = (1, 1)

    # DEBUG Print AST
    for comment in pol_copy.block_comment:
        print(f'top comA: {comment}')
    for data in pol_copy.data:
        print('\nfilter:')
        print('  header:')
        for comment in data[0].comment:
            print(f'     com: {comment}')
        for hdata in data[0].data:
            print(f'    data: {hdata}')

        for termish in data[1]:
            if isinstance(termish, TermParseData):
                print(f"{termish}")
            else:
                print(f"top comB: {termish}")
        print(f'top comC: {data[2]}')
    breakpoint()

    class FieldReprClass(Enum):
        LIST = enum.auto()
        SINGLE_VALUE = enum.auto()
        MAP = enum.auto()

        @classmethod
        def FromVarType(cls, var_type: VarType):
            # Default value is LIST
            field_repr = {
                VarType.RESTRICT_ADDRESS_FAMILY: cls.SINGLE_VALUE,
                VarType.OWNER: cls.SINGLE_VALUE,
                VarType.EXPIRATION: cls.SINGLE_VALUE,
                VarType.LOSS_PRIORITY: cls.SINGLE_VALUE,
                VarType.ROUTING_INSTANCE: cls.SINGLE_VALUE,
                VarType.PRECEDENCE: cls.SINGLE_VALUE,
                VarType.NEXT_IP: cls.SINGLE_VALUE,
                VarType.COUNTER: cls.SINGLE_VALUE,
                VarType.ENCAPSULATE: cls.SINGLE_VALUE,
                VarType.PORT_MIRROR: cls.SINGLE_VALUE,
                VarType.TRAFFIC_CLASS_COUNT: cls.SINGLE_VALUE,
                VarType.LOG_LIMIT: cls.SINGLE_VALUE,
                VarType.LOG_NAME: cls.SINGLE_VALUE,
                VarType.POLICER: cls.SINGLE_VALUE,
                VarType.PRIORITY: cls.SINGLE_VALUE,
                VarType.QOS: cls.SINGLE_VALUE,
                VarType.PACKET_LEN: cls.SINGLE_VALUE,
                VarType.FRAGMENT_OFFSET: cls.SINGLE_VALUE,
                VarType.HOP_LIMIT: cls.SINGLE_VALUE,
                VarType.SINTERFACE: cls.SINGLE_VALUE,
                VarType.DINTERFACE: cls.SINGLE_VALUE,
                VarType.TIMEOUT: cls.SINGLE_VALUE,
                VarType.DSCP_SET: cls.SINGLE_VALUE,
                VarType.VPN: cls.SINGLE_VALUE,
                VarType.TTL: cls.SINGLE_VALUE,
                VarType.FILTER_TERM: cls.SINGLE_VALUE,
                VarType.VPN: cls.SINGLE_VALUE,
                VarType.COMMENT: cls.SINGLE_VALUE,
                VarType.FLEXIBLE_MATCH_RANGE: cls.MAP,
                VarType.TARGET: cls.MAP,
                VarType.VERBATIM: cls.MAP,
            }
            return field_repr.get(var_type, cls.LIST)

    class FieldFlags(Flag):
        """Field-specific behaviors.

        Members:
            NONE: Default setting.
            OVERWRITE: The field can only have a single value per term. Only
                the final occurence of the field will count.
            NO_COLLAPSE: The field contains a list that should never be
                collapsed into a string.
            MULTILINE: The field contains a list of strings that should be concatenated
                into a single multiline string.
        """

        NONE = 0
        OVERWRITE = enum.auto()
        NO_COLLAPSE = enum.auto()
        MULTILINE = enum.auto()

        @classmethod
        def FromVarType(cls, var_type: VarType):
            field_flags = {
                VarType.RESTRICT_ADDRESS_FAMILY: cls.OVERWRITE,
                VarType.OWNER: cls.OVERWRITE,
                VarType.EXPIRATION: cls.OVERWRITE,
                VarType.LOSS_PRIORITY: cls.OVERWRITE,
                VarType.ROUTING_INSTANCE: cls.OVERWRITE,
                VarType.PRECEDENCE: cls.OVERWRITE,
                VarType.NEXT_IP: cls.OVERWRITE,
                VarType.COUNTER: cls.OVERWRITE,
                VarType.ENCAPSULATE: cls.OVERWRITE,
                VarType.PORT_MIRROR: cls.OVERWRITE,
                VarType.TRAFFIC_CLASS_COUNT: cls.OVERWRITE,
                VarType.LOG_LIMIT: cls.OVERWRITE,
                VarType.LOG_NAME: cls.OVERWRITE,
                VarType.POLICER: cls.OVERWRITE,
                VarType.PRIORITY: cls.OVERWRITE,
                VarType.QOS: cls.OVERWRITE,
                VarType.PACKET_LEN: cls.OVERWRITE,
                VarType.FRAGMENT_OFFSET: cls.OVERWRITE,
                VarType.HOP_LIMIT: cls.OVERWRITE,
                VarType.SINTERFACE: cls.OVERWRITE,
                VarType.DINTERFACE: cls.OVERWRITE,
                VarType.TIMEOUT: cls.OVERWRITE,
                VarType.DSCP_SET: cls.OVERWRITE,
                VarType.VPN: cls.OVERWRITE,
                VarType.TTL: cls.OVERWRITE,
                VarType.FILTER_TERM: cls.OVERWRITE,
                VarType.TARGET: cls.OVERWRITE,
                VarType.VPN: cls.OVERWRITE,
                VarType.FORWARDING_CLASS: cls.NO_COLLAPSE,
                VarType.FORWARDING_CLASS_EXCEPT: cls.NO_COLLAPSE,
                VarType.OPTION: cls.NO_COLLAPSE,
                VarType.TARGET_RESOURCES: cls.NO_COLLAPSE,
                VarType.VERBATIM: cls.MULTILINE,
                VarType.COMMENT: cls.MULTILINE,
            }
            return field_flags.get(var_type, cls.NONE)

    # 1. Classify comments and attach them to values.
    # 2. Process each line into term data model.

    # At this point we have our AST with imperfect comment attachment. The AST associates
    # inter-value and inter-field comments to the preceding node instead of the subsequent
    # node. This is conducive to LALR(1) parsing but must be adjusted if/when we have to
    # move a value.
    #
    # Values, fields, and comments moves are to be avoided when comments are present since
    # they can potentially jumble up comments.
    #
    # * Case 1)  A term has dead values.
    #   Here we can just replace the dead value with a comment and not move any comments or values.
    #   Only the last occurence of the field (the live value) will be uncommented.
    #   Specifically this means replacing the dead field line and all of its comments
    #   with a long block comment.
    # * Case 2) A term has multiple adjacent instances of the same field.
    #   Again we want to keep the linear sequence of elements the same, so
    #   the inter-field and field-line comments just become inter-value comments.
    # * Case 3) A term has multiple non-adjacent instances of the same field.
    #   Now the values must be consolidated which moves values plus inter-value and value-line comments.
    #   One option would be to leave behind a dead field line with the original comments.
    #   The values could be moved without comments or through duplication of comments.

    # def is_adjacent(term: TermParseData, pos0: int, pos1: int):
    #     """Determine if any field lines appear between pos0, pos1."""
    #     return all(not isinstance(term[i], VarType) for i in range(pos0 + 1, pos1))

    def append_field_line(cm: CommentedMap, term: TermParseData, pos: int):
        """UNUSED Take the field at term[pos] and append it to the CommentedMap cm."""
        field_line = term[pos]
        if not isinstance(field_line, VarType):
            return  # TODO assert

        # field_behavior = FieldBehavior.FromVarType(term[pos].var_type)
        field_key = 'temp_field'  # TODO get from field line
        output_expr = 'list'  # TODO get from field_behavior

        if field_key in cm:
            return  # TODO raise - append_field_line will not extend existing fields in the comment map

        if output_expr == 'list':
            rhs = CommentedSeq([])
        elif output_expr == 'map_abbb':
            # representation used by target, verbatim fields
            # first value expr is used as the key, rest are placed in the list
            rhs = CommentedMap({})
            key_token = None
            expr = field_line.value.pop(0)
            if isinstance(expr, ValueExpr):
                key_token = expr
            else:
                rhs.yaml_set_start_comment('\n'.join(expr))
                expr = field_line.value.pop(0)
                if not isinstance(expr, ValueExpr):
                    return  # TODO raise - parser should never generate more than one CommentExpr
                key_token = expr

        # loop thru values / comments and build up value seq
        for i, expr in enumerate(field_line.value):
            if isinstance(expr, ValueExpr):
                values.append(expr.value)
                if expr.comment:
                    values.yaml_add_eol_comment(''.join(expr.comment), len(values) - 1)
            elif isinstance(expr, CommentExpr):
                if i == 0:
                    values.yaml_set_start_comment('\n'.join(expr))
                    continue
                comment = '\n#'.join(expr)
                values.yaml_set_comment_after(pos=len(values) - 1, comment=comment)

        cm[field_key] = rhs

    # Data structure: Comment

    def rump(term: "TermParseData | HeaderParseData", pos: int):
        """Replace the field line at pos with a comment."""
        # Create an orphan CommentedMap just for the comment body
        block = CommentedMap({})
        comment_data = {}
        # Attach field as YAML to the orphan map
        block_mapping_set_field(block, comment_data, term.data[pos])
        # Produce a comment containing the YAML
        # Render the orphan map as YAML
        # Comment out the whole expression and strip version header
        def trf(s):
            return s

        buf = io.BytesIO()
        yaml.dump(block, buf, transform=trf)
        return str(buf)

    def get_target_platform(item: VarType):
        if item.var_type != VarType.TARGET:
            raise AssertionError('Expected VarType.TARGET')

        if not item.value:
            return

        if isinstance(item.value[0], ValueExpr):
            return item.value[0].value
        elif isinstance(item.value[1], ValueExpr):
            return item.value[1].value
        else:
            raise AssertionError('Expected first or second target value to include a platform')

    def get_flex_match_attr(item: VarType):
        if item.var_type != VarType.FLEXIBLE_MATCH_RANGE:
            raise AssertionError('Expected VarType.FLEXIBLE_MATCH_RANGE')

        if not item.value:
            return

        if isinstance(item.value[0], ValueExpr):
            return item.value[0].value
        elif isinstance(item.value[1], ValueExpr):
            return item.value[1].value
        else:
            raise AssertionError('Expected first or second target value to include an attribute')

    def consolidate_fields(block: "TermParseData | HeaderParseData"):
        """Consolidate repeated fields in this block so that only one field line per type
        remains and there are no dead values."""

        first_seen_map = {}  # Record first position of each field
        last_adjacent_map = {}  # Last 'adjacent' position of each field
        seen_platforms = set()  # Target platforms already seen
        seen_flexible_match_attr = set()  # Flexible match attributes already seen
        last_field = None  # Last non-comment position
        for i, item in enumerate(block.data):
            if not isinstance(item, VarType):
                continue

            first_pos = first_seen_map.get(item.var_type, None)
            if not first_pos:
                first_seen_map[item.var_type] = i
                last_adjacent_map[item.var_type] = i

                if item.var_type == VarType.TARGET:
                    platform = get_target_platform(item)
                    seen_platforms.add(platform)
                elif item.var_type == VarType.FLEXIBLE_MATCH_RANGE:
                    attr = get_flex_match_attr(item)
                    seen_flexible_match_attr.add(attr)
            else:
                field_flags = FieldFlags.FromVarType(item.var_type)
                adjacent_pos = last_adjacent_map[item.var_type]

                dead_target_line = False
                if item.var_type == VarType.TARGET:
                    platform = get_target_platform(item)
                    if platform in seen_platforms:
                        dead_target_line = True
                    else:
                        seen_platforms.add(platform)

                if item.var_type == VarType.FLEXIBLE_MATCH_RANGE:
                    attr = get_flex_match_attr(item)
                    if attr in seen_flexible_match_attr:
                        raise TypeError(
                            f'Unexpected duplicate flexible-match-range attribute. '
                            'A term was encountered with multiple values for the same flexible-match-range attribute. '
                            'When converting to YAML only a single value is allowed. '
                            'Remove the duplicate attribute from term "{block.name}" to continue.'
                        )
                    else:
                        seen_flexible_match_attr.add(attr)

                if FieldFlags.OVERWRITE in field_flags or dead_target_line:
                    # preserve dead value as a comment
                    # TODO logging.warning(f"Dead line found for {item} in term {term.name} in file {pol_copy.filename}.")
                    rump(block, first_pos)

                # consolidate adjacent fields and absorb comments in between them
                elif last_field == adjacent_pos:
                    # collect next field and inter-field comments into the top position
                    # Note this implicitly converts inter-field comments into inter-value comments
                    for j in range(adjacent_pos + 1, i + 1):
                        if not block[j]:
                            continue
                        block[first_pos].value.append(block[j])
                        block[j] = None

                    last_adjacent_map[item.var_type] = i

                # consolidate non-adjacent fields
                else:
                    # collect field values into the top position
                    # TODO probably better to strip comments here to avoid noisy duplication
                    block[first_pos].value.append(item)
                    # leave a rump comment
                    rump(block, i)
            last_field = i

    def multiline_single_value_rhs(item: VarType):
        """Construct a multiline string YAML value expression with comments."""
        # Multiline strings take up the whole line and cannot have end-of-line comments
        # So those comments must be collected above the field name
        multiline_content = []
        trailing_comment = False

        before_key_comment = []
        after_value_comment = []

        if item.field_comment:
            before_key_comment.append(item.field_comment)
        if isinstance(item.value[0], CommentExpr):
            pre_comment = item.value.pop(0)
            before_key_comment.append(pre_comment)
        content, eol_comment = item.value.pop(0)
        multiline_content.append(content)
        if eol_comment:
            before_key_comment.append(eol_comment[0])
        if item.value and isinstance(item.value[0], CommentExpr):
            post_comment = item.value.pop(0)
            before_key_comment.append(post_comment)
            trailing_comment = True

        if item.value:
            # Separate comments from values for merged field lines
            # TODO - consolidation code must drop comments in the non-adjacent case

            for merged_item in item.value:
                if not isinstance(merged_item, VarType):
                    raise AssertionError('Expected VarType')

                trailing_comment = False
                if merged_item.field_comment:
                    before_key_comment.append(merged_item.field_comment)
                if isinstance(merged_item.value[0], CommentExpr):
                    pre_comment = merged_item.value.pop(0)
                    before_key_comment.append(pre_comment)
                comment, eol_comment = merged_item.value.pop(0)
                multiline_content.append(comment)
                if eol_comment:
                    before_key_comment.append(eol_comment)
                if merged_item.value and isinstance(merged_item.value[0], CommentExpr):
                    post_comment = merged_item.value.pop(0)
                    before_key_comment.append(post_comment)
                    trailing_comment = True

        if trailing_comment:
            after_value_comment.append(before_key_comment.pop())

        rhs = LiteralScalarString('\n'.join(multiline_content))

        return rhs, before_key_comment, after_value_comment

    def single_value_rhs(item: VarType):
        """Construct a single value YAML value expression with comments."""
        before_key_comment = []
        after_value_comment = []
        eol_comment = None

        if item.field_comment:
            before_key_comment.append(item.field_comment)
        if isinstance(item.value[0], CommentExpr):
            pre_comment = item.value.pop(0)
            before_key_comment.append(pre_comment)
        value_expr = item.value.pop(0)
        rhs = value_expr.value
        eol_comment = value_expr.comment
        if eol_comment:
            eol_comment = eol_comment[0]
        if item.value:
            after_value_comment.append(item.value[0])

        return rhs, before_key_comment, eol_comment, after_value_comment

    def list_rhs(item: VarType):
        """Construct a list-style YAML value expression with comments."""
        #   [PRE_COMMENT], VALUE [EOL], [POST_COMMENT], [ VALUE [EOL], [POST_COMMENT] ]*, [List[VarType]]
        before_key_comment = []
        rhs = CommentedSeq([])
        rhs_comments = defaultdict(list)

        if item.field_comment:
            before_key_comment.append(item.field_comment)
        if isinstance(item.value[0], CommentExpr):
            pre_comment = item.value.pop(0)
            before_key_comment.append(pre_comment)

        while item.value and not isinstance(item.value[0], VarType):
            if not isinstance(item.value[0], ValueExpr):
                raise AssertionError('Expected ValueExpr')

            value_expr = item.value.pop(0)
            content = value_expr.value
            eol_comment = value_expr.comment
            rhs.append(content)
            if eol_comment:
                rhs_comments[len(rhs) - 1].append(dict(eol_comment=eol_comment[0]))

            # peek
            if item.value and isinstance(item.value[0], CommentExpr):
                post_comment = item.value.pop(0)
                post_comment = '\n# '.join(post_comment)
                rhs_comments[len(rhs) - 1].append(post_comment)
            # CommentedSeq_yaml_set_comments(rhs, len(rhs) - 1, eol_comment=eol_comment, post_comment=post_comment)

        if item.value:
            # TODO these duplicate loops could be fused with a generator function
            for merged_item in item.value:
                if not isinstance(merged_item, VarType):
                    raise AssertionError('Expected VarType')

                # field_comment, pre_comment are appended to the post_comment of the previous field
                if merged_item.field_comment:
                    rhs_comments[len(rhs) - 1].append(merged_item.field_comment)
                if isinstance(merged_item.value[0], CommentExpr):
                    pre_comment = merged_item.value.pop(0)
                    rhs_comments[len(rhs) - 1].append(pre_comment)

                while merged_item.value:
                    if not isinstance(merged_item.value[0], ValueExpr):
                        raise AssertionError('Expected ValueExpr')

                    content, eol_comment = merged_item.value.pop(0)
                    rhs.append(content)
                    if eol_comment:
                        rhs_comments[len(rhs) - 1].append(dict(eol_comment=eol_comment[0]))

                    # peek
                    if merged_item.value and isinstance(merged_item.value[0], CommentExpr):
                        post_comment = merged_item.value.pop(0)
                        post_comment = '\n# '.join(post_comment)
                        rhs_comments[len(rhs) - 1].append(post_comment)

        for pos, comments in rhs_comments.items():
            eol_comment = None
            if isinstance(comments[0], dict):
                eol_comment = comments.pop(0)['eol_comment']

            CommentedSeq_yaml_set_comments(
                rhs, pos, eol_comment=eol_comment, after_comment='\n'.join(comments)
            )
        return rhs, before_key_comment

    def vpn_rhs(item: VarType):
        """Construct a mapping YAML value expression with comments."""
        # The vpn field contains one or two values, 'name' and 'policy', with 'policy' being optional.
        #   [PRE_COMMENT], VALUE [EOL], [POST_COMMENT], [ VALUE [EOL], [POST_COMMENT] ]
        # The representation looks like this:
        # # before_key_comments
        # vpn:
        #   name: vpn_name # eol comment
        #   # after comment
        #   policy: vpn_policy # eol comment
        #   # after comment
        before_key_comment = []
        rhs = CommentedMap({})
        rhs_comments = defaultdict(list)

        if item.field_comment:
            before_key_comment.append(item.field_comment)
        if isinstance(item.value[0], CommentExpr):
            pre_comment = item.value.pop(0)
            before_key_comment.append(pre_comment)

        content, eol_comment = item.value.pop(0)
        rhs['name'] = content

        if eol_comment:
            rhs_comments['name'].append(dict(eol_comment=eol_comment[0]))

        if item.value and isinstance(item.value[0], CommentExpr):
            post_comment = item.value.pop(0)
            post_comment = '\n# '.join(post_comment)
            rhs_comments['name'].append(post_comment)

        if item.value:
            content, eol_comment = item.value.pop(0)
            rhs['policy'] = content

            if eol_comment:
                rhs_comments['policy'].append(dict(eol_comment=eol_comment[0]))

            if item.value and isinstance(item.value[0], CommentExpr):
                post_comment = item.value.pop(0)
                post_comment = '\n# '.join(post_comment)
                rhs_comments['policy'].append(post_comment)

        for key, comments in rhs_comments.items():
            eol_comment = None
            if isinstance(comments[0], dict):
                eol_comment = comments.pop(0)['eol_comment']

            CommentedMap_yaml_set_comments(
                rhs, key, eol_comment=eol_comment, after_comment='\n'.join(comments)
            )
        return rhs, before_key_comment

    def target_rhs(item: VarType):
        """Construct a mapping YAML value expression with comments."""

        # We can treat the first line as not special. There will be no before_key_comment at the top level.
        # The eol/post comments on the key line will go before the key also.
        #   [PRE_COMMENT], VALUE [EOL], [POST_COMMENT], [ VALUE [EOL], [POST_COMMENT] ]*, [List[VarType]]
        # If we pop the head from the list we should be able to use list_rhs for the rest.

        rhs = CommentedMap({})

        # unpack input into a list of lines
        lines = [item]
        lines.extend((value for value in item.value if isinstance(value, VarType)))
        item.value = [value for value in item.value if not isinstance(value, VarType)]

        for line in lines:
            before_subkey_comment = []

            if line.field_comment:
                before_subkey_comment.append(line.field_comment)
            if isinstance(line.value[0], CommentExpr):
                pre_comment = line.value.pop(0)
                before_subkey_comment.append(pre_comment)

            value_expr = line.value.pop(0)
            sub_key = value_expr.value
            sub_key_eol_comment = value_expr.comment
            # get post comment
            if sub_key_eol_comment:
                before_subkey_comment.append(sub_key_eol_comment)
            if isinstance(line.value[0], CommentExpr):
                post_comment = line.value.pop(0)
                before_subkey_comment.append(post_comment)

            if line.value:
                # before_key_comment can be safely ignored: we have already used line.field_comment
                # and there can not be a pre_comment.
                sub_rhs, _ = list_rhs(line)
            else:
                sub_rhs = None

            rhs[sub_key] = sub_rhs
            rhs.yaml_set_comment_before_after_key(sub_key, before='\n'.join(before_subkey_comment))

        return rhs

    def flexible_match_rhs(item: VarType):
        """Construct a mapping YAML value expression with comments."""

        # We can treat the first line as not special. There will be no before_key_comment at the top level.
        # The eol/post comments on the key line will go before the key also.
        #   [PRE_COMMENT], VALUE [EOL], [POST_COMMENT], VALUE [EOL], [POST_COMMENT] [List[VarType]]
        # If we pop the head from the list we should be able to use single_value for the rest.

        rhs = CommentedMap({})
        rhs_comments = defaultdict(list)
        last_sub_key = None
        start_comment = None

        # unpack input into a list of lines
        lines = [item]
        lines.extend((value for value in item.value if isinstance(value, VarType)))
        item.value = [value for value in item.value if not isinstance(value, VarType)]

        for line in lines:
            before_subkey_comment = []

            if line.field_comment:
                before_subkey_comment.append(line.field_comment)
            if isinstance(line.value[0], CommentExpr):
                pre_comment = line.value.pop(0)
                before_subkey_comment.append(pre_comment)

            sub_key, sub_key_eol_comment = line.value.pop(0)
            # get post comment
            if sub_key_eol_comment:
                before_subkey_comment.append(sub_key_eol_comment)
            if isinstance(line.value[0], CommentExpr):
                post_comment = line.value.pop(0)
                before_subkey_comment.append(post_comment)

            if before_subkey_comment:
                # Ruamel will not support placing comments both above and below a mapping entry, so
                # to place a comment above we must append it to the end of the prior comment. If
                # this is the first line we must use the mapping start comment.
                if last_sub_key:
                    rhs_comments[last_sub_key].append('\n# '.join(before_subkey_comment))
                else:
                    rhs.yaml_set_start_comment('\n# '.join(before_subkey_comment))

            if line.value:
                # before_key_comment can be safely ignored: we have already used line.field_comment
                # and there can not be a pre_comment.
                sub_rhs, _, value_eol_comment, after_value_comment = single_value_rhs(line)
                if value_eol_comment:
                    rhs_comments[sub_key].append(dict(eol_comment=value_eol_comment[0]))
                if after_value_comment:
                    rhs_comments[sub_key].append(after_value_comment)
            else:
                sub_rhs = None

            rhs[sub_key] = sub_rhs
            last_sub_key = sub_key

        for sub_key, comments in rhs_comments.items():
            eol_comment = None
            if isinstance(comments[0], dict):
                eol_comment = comments.pop(0)['eol_comment']

            CommentedMap_yaml_set_comments(
                rhs, sub_key, eol_comment=eol_comment, after_comment='\n'.join(comments)
            )
        return rhs

    def block_mapping_set_field(cm: CommentedMap, comment_data: dict, item: VarType):
        """Add a field to a CommentedMap including comments."""
        repr_type = FieldReprClass.FromVarType(item.var_type)
        field_flags = FieldFlags.FromVarType(item.var_type)
        field_name = 'TEMP_NAME'  # TODO pull from FieldLine / VarType

        if field_name in cm:
            raise AssertionError("Field already defined for this map.")

        before_key_comment = []
        value_eol_comment = None
        after_value_comment = []

        # The mapping types are all so different that we may as well handle them case-by-case:
        # (*) TARGET - only the first occurrence per platform is used
        #     TODO The consolidation pass should eliminate and rump dead target lines
        #     So the repr part is simple, after consolidation each line becomes a key-list entry.
        #     list_rhs?
        # (*) FLEXIBLE_MATCH_RANGE - theoretically each attribute must appear only once.
        #     TODO The consolidation pass should crash if an attribute appears twice.
        #     After that it's just a single value for each key.
        #     single_value_rhs?
        # (*) VERBATIM - this is the complex one where each line appends to a multiline strings.
        #     The consolidation pass will intentionally break comment linearity to keep things simple.
        #     Probably needs its own rhs code (like VPN).
        if item.var_type == VarType.VPN:
            rhs, before_key_comment = vpn_rhs(item)

        elif item.var_type == VarType.TARGET:
            rhs = target_rhs(item)

        elif item.var_type == VarType.FLEXIBLE_MATCH_RANGE:
            rhs = flexible_match_rhs(item)

        elif item.var_type == VarType.VERBATIM:
            # TODO write me
            #   [PRE_COMMENT], VALUE [EOL], [POST_COMMENT], [List[VarType]]
            # Verbatim is the weirdest case for the converter. Input lines look like this:
            #   verbatim:: juniper "verbatim pass-thru"
            #   verbatim:: juniper "verbatim pass-thru line 2"
            #   verbatim:: cisco "verbatim pass-thru"
            # Most users will group lines by platform. But it is acceptable to intersperse various platform lines.
            # In the unclustered scenario, theoretically there is a way to preserve comment linearity, but to keep
            # things simple we actually will break linearity in this case, believing that it is probably very rare.
            pass
        elif repr_type == FieldReprClass.SINGLE_VALUE:
            # NOTE: VPN is handled in a special case above
            if FieldFlags.MULTILINE in field_flags:
                rhs, before_key_comment, after_value_comment = multiline_single_value_rhs(item)
            else:
                rhs, before_key_comment, value_eol_comment, after_value_comment = single_value_rhs(
                    item
                )
        elif repr_type == FieldReprClass.LIST:
            # NOTE: lists with comments are never collapsed
            rhs, before_key_comment = list_rhs(item)

        # Set the field
        cm[field_name] = rhs

        # Set comment data
        # TODO unclear exactly when comments should be handled at the level above
        if before_key_comment or value_eol_comment or after_value_comment:
            comment_data[field_name] = dict()
            if before_key_comment:
                comment_data[field_name]['before'] = '\n# '.join(before_key_comment)
            if value_eol_comment:
                comment_data[field_name]['eol'] = '\n# '.join(value_eol_comment)
            if after_value_comment:
                comment_data[field_name]['after'] = '\n# '.join(after_value_comment)

    def block_to_mapping(block: "TermParseData | HeaderParseData"):
        """Convert a block to a CommentedMap ready to dump to YAML."""

        # TODO fields with no comments should allow for collapsing
        # and blocks with no comments should allow alphabetical key ordering.
        # A simplified set_map_field might be helpful for the block case
        simplified_path = False
        if simplified_path:
            for item in block:
                if not item:
                    continue
                # set_map_field_simplified(out, item)
        else:
            out = CommentedMap({})
            start_comments = []
            map_comments = {}
            data = block.data

            if block and isinstance(data[0], CommentedMap):
                start_comment = data.pop(0)
                start_comments.append(start_comment)

            for item in data:
                if not item:
                    continue
                if not isinstance(item, VarType):
                    raise AssertionError('Expected VarType')
                block_mapping_set_field(out, map_comments, item)

            for i, key in enumerate(out.keys()):
                if not map_comments[key]:
                    continue
                if map_comments[key]['before']:
                    if i == 0:
                        out.yaml_set_start_comment(map_comments[key]['before'])
                    else:
                        pass
            for key, comment_item in map_comments.items():
                # Because Ruamel cannot place comments both above and below a key/value expression,
                # we will only place commments below an expression and concatenate 'above' comments
                # to the prior expression. A comment above the topmost key/value expression will be
                # placed in the 'start' comment position for the mapping.

                # TODO write me
                pass
            for key, comments in map_comments.items():

                if start_comments:
                    out.yaml_set_start_comment('\n# '.join(start_comments))

                eol_comment = None
                if isinstance(comments[0], dict):
                    eol_comment = comments.pop(0)['eol_comment']

                CommentedMap_yaml_set_comments(
                    out, key, eol_comment=eol_comment, after_comment='\n'.join(comments)
                )
        return out

    pol_out = CommentedMap({"filters": CommentedSeq([])})

    # First pass: consolidate repeated fields, leave rump comment if transposing data
    # Second pass: Assemble CommentedSeq or CommentedMap for each field line.
    for filter in pol_copy.data:
        filter_out = CommentedMap({'terms': defaultdict(CommentedSeq)})
        pol_out['filters'].append(filter_out)

        header = filter[0]
        consolidate_fields(header)
        filter_out['header'] = block_to_mapping(header)

        for term in filter[1]:
            if not isinstance(term, TermParseData):
                continue
            consolidate_fields(term)
            filter_out['terms'].append(block_to_mapping(term))

    # 3a. Normalize each field according to export normalization rules.
    # 3b. Construct the export data model understood by our YAML library.

    return yaml.dump(pol_out)

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

    def _ExportHeader(header: HeaderParseData):
        """Export a filter header to a dict."""
        targets = {}
        var_data = defaultdict(list)

        for item in header.data:
            if isinstance(item, Target):
                targets[item.platform] = " ".join(item.options)

            elif isinstance(item, VarType):
                var_data[item.var_type].append(item)

            elif isinstance(item, list):
                var_data[item[0].var_type].extend(item)

            elif isinstance(item, str):
                print('============= BLOCK COMMENT ========')

        result_header = {}
        result_header['targets'] = targets
        if var_data[VarType.COMMENT]:
            result_header['comment'] = '\n'.join(var_data[VarType.COMMENT])
            del var_data[VarType.COMMENT]

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
        elif isinstance(obj, VarType):
            return obj.value
        elif isinstance(obj, list):
            return [_RestoreValue(item) for item in obj]
        else:
            return obj

    def _ExportTerm(termish: TermParseData):
        """Export a term to a dict."""

        # Restore includes that were set aside
        if termish.name and termish.name in include_placeholders:
            include_path = termish.comment[1]
            include_path = pathlib.Path(include_path).with_suffix('.yaml')
            return {'include': str(include_path)}

        var_data = defaultdict(list)

        for item in termish.data:
            if isinstance(item, VarType):
                var_data[item.var_type].append(str(item))

            elif isinstance(item, str):
                print('============= BLOCK COMMENT ========')

        result_term = {}
        result_term['name'] = termish.name
        if var_data[VarType.COMMENT]:
            result_term['comment'] = '\n'.join(var_data[VarType.COMMENT])
            del var_data[VarType.COMMENT]

        if var_data[VarType.FLEXIBLE_MATCH_RANGE]:
            result_term['flexible-match-range'] = {
                item[0]: item[1] for item in var_data[VarType.FLEXIBLE_MATCH_RANGE]
            }
            del var_data[VarType.FLEXIBLE_MATCH_RANGE]

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
