# Copyright 2024 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Nokia SR OS JSON IP filter and CPM filter generator.

Generates ACL filters for Nokia SROS devices in the YANG JSON format
used by the nokia-conf model.

Target syntax:
  target:: nokiasros <filter-name> [inet|inet6|mixed] [accept|drop] [syslog-profile <N>]
  target:: nokiasros <any-name> cpm [inet|inet6] [syslog-profile <N>]

Filter options (ip-filter mode):
  inet             - generate IPv4 filter (default)
  inet6            - generate IPv6 filter
  mixed            - generate an IPv4 and an IPv6 filter with the same name
  accept           - set default-action to accept (default: drop)
  drop             - set default-action to drop
  pktlenfilter     - set filter type to packet-length

  syslog-profile N - filter log ID for log entries, 101-199 (default: 102)

Filter options (cpm mode):
  cpm              - render as a CPM filter (nokia-conf:admin-state wrapper)
  inet             - IPv4 CPM filter (default)
  inet6            - IPv6 CPM filter
  syslog-profile N - filter log ID for log entries, 101-199 (default: 102)

Unknown, repeated or conflicting options (e.g. both inet and inet6) are
rejected.  Terms with logging:: disable are not logged.

Both modes expand addresses to individual prefixes.  The only behavioural
difference in CPM mode is that tcp-established is rendered as
tcp-flags {ack: true} instead of the ip-filter tcp-established leaf.

CPM filter comments: the CPM YANG model has no top-level description leaf, so
a header comment is prepended to the first entry's description field as
"<comment> | <term-description>".

Output is always a JSON list with one item per filter, keyed by its type:
ip-filter, ipv6-filter, cpm-ip-filter or cpm-ipv6-filter.
"""

import copy
import dataclasses
import json
from typing import Any

from absl import logging

from aerleon.lib import aclgenerator
from aerleon.lib import policy as policy_module
from aerleon.lib.policy import Term as PolicyTerm


class Error(aclgenerator.Error):
    pass


class TcpEstablishedWithNonTcpError(Error):
    pass


class FirstFragmentInCpmError(Error):
    pass


class EntryIdOverflowError(Error):
    pass


class TtlHopLimitWithoutPacketLengthError(Error):
    pass


class InvalidHopLimitError(Error):
    pass


class UnsupportedFilterOptionError(Error):
    pass


class InvalidSyslogProfileError(Error):
    pass


@dataclasses.dataclass
class _FilterOptions:
    """Parsed target options of one filter."""

    address_family: str = 'inet'
    default_action: str = 'drop'
    packet_length: bool = False
    syslog_profile: int = 102


class SROSTerm(aclgenerator.Term):
    """Converts a policy term into SROS filter entry dicts."""

    ACTION_MAP = {'accept': 'accept', 'deny': 'drop', 'reject': 'drop'}
    # Protocols that SROS does not accept by name and must be expressed numerically.
    PROTO_NAME_TO_NUM = {'esp': 50}

    def __init__(
        self,
        term: PolicyTerm,
        inet_version: str = 'inet',
        syslog_profile: int = 102,
        cpm_mode: bool = False,
        mixed: bool = False,
        packet_length: bool = False,
    ) -> None:
        super().__init__(term)
        self.inet_version = inet_version
        self.syslog_profile = syslog_profile
        self.cpm_mode = cpm_mode
        self.mixed = mixed
        self.packet_length = packet_length
        self.term.FlattenAll()

    def ConvertToEntries(self) -> list[dict[str, Any]]:
        """Explode this term into a list of SROS filter entry dicts."""
        action_key = self.ACTION_MAP[self.term.action[0]]
        term_af = self.AF_MAP[self.inet_version]

        protos_of_other_af = {'icmpv6', 'icmp6'} if self.inet_version == 'inet' else {'icmp'}
        if protos_of_other_af & set(self.term.protocol):
            if not self.mixed:
                logging.warning(
                    self.NO_AF_LOG_PROTO.substitute(
                        term=self.term.name,
                        proto=', '.join(self.term.protocol),
                        af=self.inet_version,
                    )
                )
            return []

        # IP options only exist in the IPv4 header. Skip the term rather than drop
        # the match, which would widen it to every packet.
        if self.inet_version == 'inet6' and 'ip-options' in map(str, self.term.option):
            if not self.mixed:
                logging.warning(
                    self.NO_AF_LOG_PROTO.substitute(
                        term=self.term.name, proto='ip-options', af=self.inet_version
                    )
                )
            return []

        # ttl only exists in the IPv4 header and hop-limit in the IPv6 one. Skip a
        # term that only matches on the other family's field rather than drop the
        # match, which would widen it to every packet.
        self.hop_key, self.hop_match = self._HopMatch()
        if self.hop_key is None and (self.term.ttl is not None or self.term.hop_limit is not None):
            if not self.mixed:
                logging.warning(
                    self.NO_AF_LOG_PROTO.substitute(
                        term=self.term.name,
                        proto='hop-limit' if self.inet_version == 'inet' else 'ttl',
                        af=self.inet_version,
                    )
                )
            return []

        saddrs = self.term.GetAddressOfVersion('flattened_saddr', term_af)
        if self.term.flattened_saddr and not saddrs:
            self._LogNoAF('source')
            return []
        daddrs = self.term.GetAddressOfVersion('flattened_daddr', term_af)
        if self.term.flattened_daddr and not daddrs:
            self._LogNoAF('destination')
            return []
        saddrs = saddrs or ['any']
        daddrs = daddrs or ['any']
        sports = self.term.source_port or [(0, 0)]
        dports = self.term.destination_port or [(0, 0)]
        protos = self.term.protocol or [None]

        icmp_types: list[int | None] = [None]
        if self.term.icmp_type:
            icmp_map = self.ICMP_TYPE[term_af]
            resolved = [icmp_map[t] for t in self.term.icmp_type if t in icmp_map]
            if not resolved:
                return []
            icmp_types = resolved  # type: ignore[assignment]

        icmp_codes: list[int | None] = self.term.icmp_code or [None]

        opts = [str(x) for x in self.term.option]
        if 'established' in opts and self.term.protocol == ['tcp']:
            opts.append('tcp-established')
        if 'tcp-established' in opts:
            if self.term.protocol != ['tcp']:
                raise TcpEstablishedWithNonTcpError(
                    f'tcp-established can only be used with tcp protocol in term {self.term.name}'
                )

        action: dict[str, Any] = {action_key: [None]}
        if self.term.policer:
            action['rate-limit'] = {'policer': str(self.term.policer)}

        log = bool(self.term.logging) and 'disable' not in [x.value for x in self.term.logging]

        entries = []
        for saddr in saddrs:
            for daddr in daddrs:
                for sport in sports:
                    for dport in dports:
                        for proto in protos:
                            for icmp_type in icmp_types:
                                for icmp_code in icmp_codes:
                                    match = self._BuildMatch(
                                        saddr,
                                        daddr,
                                        sport,
                                        dport,
                                        proto,
                                        icmp_type,
                                        icmp_code,
                                        opts,
                                    )
                                    desc = (
                                        ' '.join(self.term.comment)
                                        if self.term.comment
                                        else self.term.name
                                    )
                                    entry: dict[str, Any] = {
                                        'description': desc,
                                        'action': copy.deepcopy(action),
                                    }
                                    if match:
                                        entry['match'] = match
                                    if log:
                                        entry['log'] = self.syslog_profile
                                    entries.append(entry)
        return entries

    def _LogNoAF(self, direction: str) -> None:
        if not self.mixed:
            logging.warning(
                self.NO_AF_LOG_ADDR.substitute(
                    term=self.term.name, direction=direction, af=self.inet_version
                )
            )

    def _HopMatch(self) -> tuple[str | None, dict[str, Any] | None]:
        """Return the ttl (IPv4) or hop-limit (IPv6) match of this filter's family.

        ttl only applies to IPv4 filters and hop-limit only to IPv6 filters; returns
        (None, None) if the term has no match for this family. A value is matched
        exactly, an 'N-M' range as a range. SR OS only matches them in
        packet-length filters, which CPM filters cannot be.
        """
        if self.term.ttl is None and self.term.hop_limit is None:
            return None, None
        if not self.packet_length:
            raise TtlHopLimitWithoutPacketLengthError(
                f'ttl and hop-limit require a packet-length filter (pktlenfilter option)'
                f' in term {self.term.name}'
            )
        if self.inet_version == 'inet6':
            key, value = 'hop-limit', self.term.hop_limit
        else:
            key, value = 'ttl', self.term.ttl
        if value is None:
            return None, None

        low, high = policy_module.TtlRange(value)
        if not 0 <= low <= high <= 255:
            raise InvalidHopLimitError(f'invalid {key} {value} in term {self.term.name}')
        if low == high:
            return key, {'eq': low}
        return key, {'range': {'start': low, 'end': high}}

    def _BuildMatch(
        self,
        saddr: Any,
        daddr: Any,
        sport: tuple[int, int],
        dport: tuple[int, int],
        proto: int | str | None,
        icmp_type: int | None,
        icmp_code: int | None,
        opts: list[str],
    ) -> dict[str, Any]:
        match: dict[str, Any] = {}

        if saddr != 'any':
            match['src-ip'] = {'address': str(saddr)}
        if daddr != 'any':
            match['dst-ip'] = {'address': str(daddr)}

        s_start, s_end = sport
        if not (s_start == s_end == 0):
            match['src-port'] = (
                {'eq': s_start}
                if s_start == s_end
                else {'range': {'start': s_start, 'end': s_end}}
            )

        d_start, d_end = dport
        if not (d_start == d_end == 0):
            match['dst-port'] = (
                {'eq': d_start}
                if d_start == d_end
                else {'range': {'start': d_start, 'end': d_end}}
            )

        if proto is not None:
            if isinstance(proto, str):
                proto_name = proto
            else:
                proto_name = self.PROTO_MAP_BY_NUMBER.get(proto) or str(proto)
            proto_val: str | int = self.PROTO_NAME_TO_NUM.get(proto_name, proto_name)
            if self.inet_version == 'inet6':
                match['next-header'] = 'ipv6-icmp' if proto_name == 'icmpv6' else proto_val
            else:
                match['protocol'] = proto_val

        if icmp_type is not None:
            icmp: dict[str, int] = {'type': icmp_type}
            if icmp_code is not None:
                icmp['code'] = icmp_code
            match['icmp'] = icmp

        if self.hop_key:
            match[self.hop_key] = copy.deepcopy(self.hop_match)

        if 'tcp-established' in opts:
            if self.cpm_mode:
                match['tcp-flags'] = {'ack': True}
            else:
                match['tcp-established'] = [None]

        if 'first-fragment' in opts:
            if self.cpm_mode:
                raise FirstFragmentInCpmError(
                    f'first-fragment is not supported in CPM filters in term {self.term.name}'
                )
            match['fragment'] = 'first-only'
        elif 'is-fragment' in opts or 'fragments' in opts:
            match['fragment'] = 'true'

        if 'ip-options' in opts:
            match['option-present'] = True

        return match


class NokiaSROS(aclgenerator.ACLGenerator):
    """Nokia SR OS JSON IP-filter and CPM-filter generator."""

    _PLATFORM = 'nokiasros'
    SUFFIX = '.sros_acl'
    _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
    _ENTRY_ID_BLOCK = 1000
    _IP_FILTER_MAX_ENTRY_ID = 2097151
    _CPM_FILTER_MAX_ENTRY_ID = 131072
    _IP_FILTER_KEY = {'inet': 'ip-filter', 'inet6': 'ipv6-filter'}
    _CPM_FILTER_KEY = {'inet': 'cpm-ip-filter', 'inet6': 'cpm-ipv6-filter'}
    # types-filter:filter-log-id, referenced by the ip-filter and CPM filter log leaf.
    _SYSLOG_PROFILE_MIN = 101
    _SYSLOG_PROFILE_MAX = 199
    # Option -> group; at most one option per group may be given.
    _COMMON_OPTIONS = {
        'inet': 'address family',
        'inet6': 'address family',
        'syslog-profile': 'syslog-profile',
    }
    _IP_FILTER_OPTIONS = {
        **_COMMON_OPTIONS,
        'mixed': 'address family',
        'accept': 'default action',
        'drop': 'default action',
        'pktlenfilter': 'pktlenfilter',
    }
    _CPM_FILTER_OPTIONS = {**_COMMON_OPTIONS, 'cpm': 'cpm'}

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_tokens -= {'verbatim'}
        supported_tokens |= {'logging', 'hop_limit', 'icmp_code', 'policer', 'ttl'}
        supported_sub_tokens['action'] = {'accept', 'deny'}
        supported_sub_tokens['option'] = {
            'established',
            'tcp-established',
            'is-fragment',
            'first-fragment',
            'fragments',
            'ip-options',
        }
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: Any, exp_info: int) -> None:
        self.total_rule_count = 0
        self.ip_filters: list[dict[str, Any]] = []

        for header, terms in pol.filters:
            filter_name = header.FilterName(self._PLATFORM)
            # Skip the filter name; slicing also leaves the header's list untouched.
            options = header.FilterOptions(self._PLATFORM)[1:]

            comment = ' '.join(header.comment) if header.comment else None
            is_cpm = filter_name == 'cpm' or 'cpm' in options
            filter_options = self._ParseFilterOptions(filter_name, options, is_cpm)
            if is_cpm:
                self._TranslateCPMFilter(filter_options, terms, comment)
            else:
                self._TranslateIPFilter(filter_name, filter_options, terms, comment)

    def _ParseFilterOptions(
        self, filter_name: str, options: list[str], is_cpm: bool
    ) -> _FilterOptions:
        """Parse the target options that follow the filter name."""
        allowed = self._CPM_FILTER_OPTIONS if is_cpm else self._IP_FILTER_OPTIONS
        kind = 'CPM' if is_cpm else 'IP'
        parsed = _FilterOptions()
        seen: dict[str, str] = {}
        tokens = iter(options)
        for opt in tokens:
            group = allowed.get(opt)
            if group is None:
                raise UnsupportedFilterOptionError(
                    f'unsupported option {opt!r} in {kind} filter {filter_name}'
                )
            if group in seen:
                raise UnsupportedFilterOptionError(
                    f'more than one {group} option ({seen[group]!r}, {opt!r})'
                    f' in {kind} filter {filter_name}'
                )
            seen[group] = opt
            if group == 'address family':
                parsed.address_family = opt
            elif group == 'default action':
                parsed.default_action = opt
            elif opt == 'pktlenfilter':
                parsed.packet_length = True
            elif opt == 'syslog-profile':
                parsed.syslog_profile = self._ParseSyslogProfile(filter_name, next(tokens, None))
        return parsed

    def _ParseSyslogProfile(self, filter_name: str, value: str | None) -> int:
        try:
            profile = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            profile = None
        if profile is None or not (
            self._SYSLOG_PROFILE_MIN <= profile <= self._SYSLOG_PROFILE_MAX
        ):
            raise InvalidSyslogProfileError(
                f'syslog-profile must be an integer from {self._SYSLOG_PROFILE_MIN}'
                f' to {self._SYSLOG_PROFILE_MAX}, got {value!r} in filter {filter_name}'
            )
        return profile

    def _TranslateIPFilter(
        self,
        filter_name: str,
        filter_options: _FilterOptions,
        terms: list[Any],
        comment: str | None = None,
    ) -> None:
        address_family = filter_options.address_family
        packet_length = filter_options.packet_length
        afs = ['inet', 'inet6'] if address_family == 'mixed' else [address_family]
        for af in afs:
            term_entries = [
                SROSTerm(
                    self.FixHighPorts(term, af=af),
                    af,
                    filter_options.syslog_profile,
                    mixed=address_family == 'mixed',
                    packet_length=packet_length,
                ).ConvertToEntries()
                for term in terms
            ]
            entries = self._NumberEntries(term_entries, self._IP_FILTER_MAX_ENTRY_ID)

            filter_dict: dict[str, Any] = {'nokia-conf:scope': 'template'}
            if packet_length:
                filter_dict['nokia-conf:type'] = 'packet-length'
            if comment:
                filter_dict['nokia-conf:description'] = comment
            filter_dict['nokia-conf:default-action'] = filter_options.default_action
            filter_dict['nokia-conf:filter-name'] = filter_name
            filter_dict['nokia-conf:entry'] = entries
            self.ip_filters.append({self._IP_FILTER_KEY[af]: filter_dict})

    def _TranslateCPMFilter(
        self,
        filter_options: _FilterOptions,
        terms: list[Any],
        comment: str | None = None,
    ) -> None:
        address_family = filter_options.address_family
        term_entries = [
            SROSTerm(
                self.FixHighPorts(term, af=address_family),
                address_family,
                filter_options.syslog_profile,
                cpm_mode=True,
            ).ConvertToEntries()
            for term in terms
        ]
        entries = self._NumberEntries(term_entries, self._CPM_FILTER_MAX_ENTRY_ID)

        if comment and entries:
            entries[0]['description'] = f"{comment} | {entries[0]['description']}"

        cpm_dict: dict[str, Any] = {'nokia-conf:admin-state': 'enable'}
        cpm_dict['nokia-conf:entry'] = entries
        self.ip_filters.append({self._CPM_FILTER_KEY[address_family]: cpm_dict})

    def _NumberEntries(
        self, term_entries: list[list[dict[str, Any]]], max_entry_id: int
    ) -> list[dict[str, Any]]:
        """Assign entry-ids in fixed per-term blocks."""
        block = self._ENTRY_ID_BLOCK
        entries = []
        for term_idx, per_term in enumerate(term_entries, start=1):
            if len(per_term) > block:
                raise EntryIdOverflowError(
                    f'term {term_idx} expands to {len(per_term)} entries,'
                    f' more than the {block} allowed per term'
                )
            for offset, entry in enumerate(per_term):
                entry_id = term_idx * block + offset
                if entry_id > max_entry_id:
                    raise EntryIdOverflowError(
                        f'entry-id {entry_id} exceeds the maximum of {max_entry_id}'
                        f' ({len(term_entries)} terms)'
                    )
                entry['entry-id'] = entry_id
                entries.append(entry)
        self.total_rule_count += len(entries)
        return entries

    def __str__(self) -> str:
        return json.dumps(self.ip_filters, indent=4) + '\n'
