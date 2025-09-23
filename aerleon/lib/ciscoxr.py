# Copyright 2011 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
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
#

"""Cisco IOS-XR filter renderer."""
from __future__ import annotations

from aerleon.lib import cisco
from aerleon.lib.policy import Term


class CiscoXR(cisco.Cisco):
    """A cisco policy object."""

    _PLATFORM = 'ciscoxr'
    _DEFAULT_PROTOCOL = 'ip'
    SUFFIX = '.xacl'
    _PROTO_INT = False

    def _AppendTargetByFilterType(self, filter_name: str, filter_type: str) -> list[str]:
        """Takes in the filter name and type and appends headers.

        Args:
          filter_name: Name of the current filter
          filter_type: Type of current filter

        Returns:
          list of strings
        """
        target = []
        if filter_type == 'inet6':
            target.append(f'no ipv6 access-list {filter_name}')
            target.append(f'ipv6 access-list {filter_name}')
        else:
            target.append(f'no ipv4 access-list {filter_name}')
            target.append(f'ipv4 access-list {filter_name}')
        return target

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()

        supported_tokens |= {'next_ip'}

        return supported_tokens, supported_sub_tokens

    def _GetObjectGroupTerm(self, term: Term, verbose: bool = True) -> CiscoXRObjectGroupTerm:
        """Returns an ObjectGroupTerm object."""
        return CiscoXRObjectGroupTerm(term, platform=self._PLATFORM, verbose=verbose)


class CiscoXRObjectGroupTerm(cisco.ObjectGroupTerm):
    ALLOWED_PROTO_STRINGS = cisco.ExtendedTerm.ALLOWED_PROTO_STRINGS + ['pcp', 'esp']
