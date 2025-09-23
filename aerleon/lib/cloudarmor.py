# Copyright 2018-2021 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
"""Google Cloud Armor Firewall Generator.

Refer to the links below for more information
https://cloud.google.com/armor/
https://cloud.google.com/armor/docs/
"""

import copy
import json
from typing import TypedDict

from absl import logging

from aerleon.lib import aclgenerator, policy


# Generic error class
class Error(aclgenerator.Error):
    """Generic error class."""


class ExceededMaxTermsError(Error):
    """Raised when number of terms in a policy exceed _MAX_RULES_PER_POLICY."""


class UnsupportedFilterTypeError(Error):
    """Raised when unsupported filter type (i.e address family) is specified."""


class RuleMatchConfig(TypedDict):
    srcIpRanges: 'list[str]'


class RuleMatch(TypedDict):
    config: RuleMatchConfig
    versionedExpr: str


class PolicyRule(TypedDict):
    action: str
    description: str
    match: RuleMatch
    preview: bool
    priority: int


class Term(aclgenerator.Term):
    """Generates the Term for CloudArmor."""

    # Max srcIpRanges within a single term
    _MAX_IP_RANGES_PER_TERM = 5

    ACTION_MAP = {'accept': 'allow', 'deny': 'deny(404)'}

    _MAX_TERM_COMMENT_LENGTH = 64

    def __init__(
        self, term: policy.Term, address_family: str = 'inet', verbose: bool = True
    ) -> None:
        super().__init__(term)
        self.term = term
        self.address_family = address_family
        self.verbose = verbose

    def __str__(self) -> str:
        return ''

    def ConvertToDict(self, priority_index: int) -> list[PolicyRule]:
        """Converts term to dictionary representation of CloudArmor's JSON format.

        Takes all of the attributes associated with a term (match, action, etc) and
        converts them into a dictionary which most closely represents
        the CloudArmor API's JSON rule format. Additionally, splits a single term
        into multiple terms if the number of srcIpRanges exceed
        _MAX_IP_RANGES_PER_TERM.

        Args:
          priority_index: An integer priority value assigned to the term. In case
            the term is split into i sub-terms, the ith sub-term has
            priority = priority_index + i

        Returns:
          A list of dicts where each dict is a term

        Raises:
          UnsupportedFilterTypeError: Raised when an unsupported filter type is
            specified
        """
        term_dict = {}
        rules = []

        if self.term.comment and self.verbose:
            raw_comment = ' '.join(self.term.comment)
            if len(raw_comment) > self._MAX_TERM_COMMENT_LENGTH:
                term_dict['description'] = raw_comment[: self._MAX_TERM_COMMENT_LENGTH]
                logging.warning(
                    'Term comment exceeds maximum length = %d; Truncating ' 'comment..',
                    self._MAX_TERM_COMMENT_LENGTH,
                )
            else:
                term_dict['description'] = raw_comment

        term_dict['action'] = self.ACTION_MAP[self.term.action[0]]
        term_dict['preview'] = False

        if self.address_family == 'inet':
            saddrs = self.term.GetAddressOfVersion('source_address', 4)
        elif self.address_family == 'inet6':
            saddrs = self.term.GetAddressOfVersion('source_address', 6)
        elif self.address_family == 'mixed':
            saddrs = self.term.GetAddressOfVersion(
                'source_address', 4
            ) + self.term.GetAddressOfVersion('source_address', 6)
        else:
            raise UnsupportedFilterTypeError(
                f"'{self.address_family}' is not a valid filter type"
            )

        term_dict['match'] = {
            'versionedExpr': 'SRC_IPS_V1',
            'config': {
                'srcIpRanges': saddrs,
            },
        }
        # If scrIpRanges within a single term exceed _MAX_IP_RANGES_PER_TERM,
        # split into multiple terms
        source_addr_chunks = [
            saddrs[x : x + self._MAX_IP_RANGES_PER_TERM]
            for x in range(0, len(saddrs), self._MAX_IP_RANGES_PER_TERM)
        ]

        if not source_addr_chunks:
            rule = copy.deepcopy(term_dict)
            rule['priority'] = priority_index
            rule['match']['config']['srcIpRanges'] = ['*']
            rules.append(rule)

        else:
            split_rule_count = len(source_addr_chunks)
            for i, chunk in enumerate(source_addr_chunks):
                rule = copy.deepcopy(term_dict)
                if split_rule_count > 1:
                    term_position_suffix = ' [%d/%d]' % (i + 1, split_rule_count)
                    desc_limit = self._MAX_TERM_COMMENT_LENGTH - len(term_position_suffix)
                    rule['description'] = (
                        rule.get('description', '')[:desc_limit] + term_position_suffix
                    )

                rule['priority'] = priority_index + i
                rule['match'] = {
                    'versionedExpr': 'SRC_IPS_V1',
                    'config': {
                        'srcIpRanges': [str(saddr) for saddr in chunk],
                    },
                }
                rules.append(rule)

        if len(source_addr_chunks) > 1:
            logging.debug(
                f'Current term {self.term.name} was split into {len(source_addr_chunks)} sub-terms since '
                '_MAX_IP_RANGES_PER_TERM was exceeded',
            )
        return rules


class CloudArmor(aclgenerator.ACLGenerator):
    """A CloudArmor policy object."""

    _PLATFORM = 'cloudarmor'
    SUFFIX = '.gca'
    _SUPPORTED_AF = {'inet', 'inet6', 'mixed'}

    # Maximum number of rules that a CloudArmor policy can contain
    _MAX_RULES_PER_POLICY = 200

    # Warn user when rule count exceeds this number
    _RULECOUNT_WARN_THRESHOLD = 190

    # Maps indiviudal filter options to their index positions in the POL header
    _FILTER_OPTIONS_MAP = {'filter_type': 0}

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        supported_tokens, _ = super()._BuildTokens()
        supported_tokens -= {
            'destination_address',
            'destination_address_exclude',
            'destination_port',
            'expiration',
            'icmp_type',
            'stateless_reply',
            'option',
            'protocol',
            'platform',
            'platform_exclude',
            'source_address_exclude',
            'source_port',
            'verbatim',
        }
        supported_sub_tokens = {'action': {'accept', 'deny'}}
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        """Translates a Aerleon policy into a CloudArmor-specific data structure.

        Takes in a POL file, parses each term and populates the cloudarmor_policies
        list. Each term in this list is a dictionary formatted according to
        CloudArmor's rule API specification.

        Args:
          pol: A Policy() object representing a given POL file.
          exp_info: An int that specifies number of weeks till policy expiry.

        Raises:
          ExceededMaxTermsError: Raised when the number of terms in a policy exceed
            _MAX_RULES_PER_POLICY.

          UnsupportedFilterTypeError: Raised when an unsupported filter type is
            specified
        """
        self.cloudarmor_policies = []

        for header, terms in pol.filters:
            filter_options = header.FilterOptions(self._PLATFORM)
            verbose = True
            if 'noverbose' in filter_options:
                filter_options.remove('noverbose')
                verbose = False

            if filter_options is None or not filter_options:
                filter_type = 'inet'
                logging.warning('No filter_type specified. Defaulting to inet (IPv4)')

            else:
                filter_type = filter_options[self._FILTER_OPTIONS_MAP['filter_type']]
                if filter_type not in self._SUPPORTED_AF:
                    raise UnsupportedFilterTypeError(
                        f"'{filter_type}' is not a valid filter type"
                    )

            counter = 1

            for term in terms:
                json_rule_list = Term(
                    term, address_family=filter_type, verbose=verbose
                ).ConvertToDict(priority_index=counter)
                # count number of rules generated after split (if any)
                split_rule_count = len(json_rule_list)

                self.cloudarmor_policies.extend(json_rule_list)

                counter = counter + split_rule_count

                total_rule_count = len(self.cloudarmor_policies)

                if total_rule_count > self._RULECOUNT_WARN_THRESHOLD:
                    if total_rule_count > self._MAX_RULES_PER_POLICY:
                        raise ExceededMaxTermsError(
                            'Exceeded maximum number of rules in '
                            ' a single policy | MAX = %d' % self._MAX_RULES_PER_POLICY
                        )
                    else:
                        logging.warning(
                            'Current rule count (%d) is almost at maximum ' 'limit of %d',
                            total_rule_count,
                            self._MAX_RULES_PER_POLICY,
                        )

    def __str__(self) -> str:
        """Return the JSON blob for CloudArmor."""

        out = '%s\n\n' % (
            json.dumps(self.cloudarmor_policies, indent=2, separators=(',', ': '), sort_keys=True)
        )
        return out
