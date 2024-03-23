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

"""Common library for network ports and protocol handling."""
from __future__ import annotations

import logging
from typing import Tuple


class Error(Exception):
    """Base error class."""


class BadPortValue(Error):
    """Invalid port format."""


class BadPortRange(Error):
    """Out of bounds port range."""


class InvalidRange(Error):
    """Range is not valid (eg, single port)."""


class NotSinglePort(Error):
    """Port range defined instead of a single port."""


class PPP:
    """PPP: [P]ort [P]rotocol [P]airs.

    Make port/protocol pairs an object for easy comparisons
    """

    service: str
    port: str
    protocol: str
    nested: bool

    def __init__(self, service, token=None) -> None:
        """Init for PPP object.

        Args:
          service: A port/protocol pair as str (eg: '80/tcp', '22-23/tcp') or
                   a nested service name (eg: 'SSH')
        """
        # remove comments (if any)
        self.service = service.split('#')[0].strip()
        self.nested=True
        self.port = None
        self.protocol = None
        self.is_range = False
        self.is_single_port = True
        self.start = None
        self.end = None
        self.token = token
        if '/' in self.service:
            self.port = self.service.split('/')[0]
            self.protocol = self.service.split('/')[1]
            self.nested = False
            if '-' in self.port:
                self.start = int(self.port.split('-')[0])
            else:
                self.start = int(self.port)
            if '-' in self.port:
                self.end = int(self.port.split('-')[1])
            else:
                self.end = int(self.port)
            if '-' in self.port and self.start != self.end:
                self.is_range = True
            self.is_single_port = not self.is_range
            

    def __contains__(self, other: PPP):
        # determine if a PPP object is contained within another.
        return (
            (self.start <= other.start)
            and (other.end <= self.end)
            and self.protocol == other.protocol
        )
    @staticmethod
    def _tupleToPPP(t:Tuple):
        logging.warning("Comparing a Tuple to PPP object will be deprecated soon.")
        return PPP(f'{t[0]}-{t[1]}/na')

    def __lt__(self, other: PPP):
        if isinstance(other, Tuple):
            other = self._tupleToPPP(other)

        return (self.start, self.end) < (other.start, other.end)

    def __gt__(self, other: PPP):
        if isinstance(other, Tuple):
            other = self._tupleToPPP(other)
        return (self.start, self.end) > (other.start, other.end)

    def __le__(self, other: PPP):
        if isinstance(other, Tuple):
            other = self._tupleToPPP(other)
        return (self.start, self.end) <= (other.start, other.end)
        
    def __ge__(self, other: PPP):
        if isinstance(other, Tuple):
            other = self._tupleToPPP(other)
        return (self.start, self.end) >= (other.start, other.end)

    def __eq__(self, other: PPP):
        if isinstance(other, Tuple):
            other = self._tupleToPPP(other)
        return (self.start, self.end) == (other.start, other.end)

    def __str__(self):
        port = self.service

        if self.is_range:
            port = f"{self.start}-{self.end}/{self.protocol}"
        if self.is_single_port:
            port = f"{self.port}/{self.protocol}"
        if self.token:
            port = f"{port} {self.token}"
        return f"PPP(\"{port}\")"
    
    def __repr__(self):
        return self.__str__()
    def split(self, sep: str):
        logging.warn("Split is used to preserve backwards compatibility and will be deprecated.")
        return self.service.split('/')[0].split(sep)

    def __getitem__(self, index):
        logging.warn(
            "Subscripting is used to preserve backwards compatibility and will be deprecated."
        )
        return [self.start, self.end][index]
    
    def __len__(self):
        if self.start == self.end:
            return 1
        return 2


def Port(port):
    """Sanitize a port value.

    Args:
      port: a port value

    Returns:
      port: a port value

    Raises:
      BadPortValue: port is not valid integer or string
      BadPortRange: port is outside valid range
    """
    pval = -1
    try:
        pval = int(port)
    except ValueError:
        raise BadPortValue('port %s is not valid.' % port)
    if pval < 0 or pval > 65535:
        raise BadPortRange('port %s is out of range 0-65535.' % port)
    return pval