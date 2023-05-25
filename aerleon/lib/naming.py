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

"""Parse naming definition files.

Network access control applications use definition files which contain
information about networks and services.  This naming class
will provide an easy interface into using these definitions.

Sample usage with definition files contained in ./acl/defs:
    defs = Naming('acl/defs/')

    services =  defs.GetService('DNS')
      returns ['53/tcp', '53/udp', ...]

    networks = defs.GetNet('INTERNAL')
      returns a list of nacaddr.IPv4 object

The definition files are contained in a single directory and
may consist of multiple files ending in .net or .svc extensions,
indicating network or service definitions respectively.  The
format of the files consists of a 'token' value, followed by a
list of values and optional comments, such as:

INTERNAL = 10.0.0.0/8     # RFC-1918
           172.16.0.0/12  # RFC-1918
           192.168.0.0/16 # RFC-1918
or

DNS = 53/tcp
      53/udp

"""


import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple, Union

if sys.version_info > (3, 11):
    from typing import Self
else:
    from typing import TypeVar

    Self = TypeVar("Self", bound="_ItemUnit")

import yaml
from absl import logging
from yaml import YAMLError

from aerleon.lib import nacaddr
from aerleon.lib import port as portlib
from aerleon.lib.nacaddr import IPv4, IPv6
from aerleon.lib.yaml_loader import SpanSafeYamlLoader

DEF_TYPE_SERVICES = 'services'
DEF_TYPE_NETWORKS = 'networks'


class Error(Exception):
    """Create our own base error class to be inherited by other error classes."""


class NamespaceCollisionError(Error):
    """Used to report on duplicate symbol names found while parsing."""


class BadNetmaskTypeError(Error):
    """Used to report on duplicate symbol names found while parsing."""


class NoDefinitionsError(Error):
    """Raised if no definitions are found."""


class ParseError(Error):
    """Raised if an error occurs during parsing."""


class UndefinedAddressError(Error):
    """Raised if an address is referenced but not defined."""


class UndefinedServiceError(Error):
    """Raised if a service is referenced but not defined."""


class UndefinedPortError(Error):
    """Raised if a port/protocol pair has not been defined."""


class UnexpectedDefinitionTypeError(Error):
    """An unexpected/unknown definition type was used."""


class NamingSyntaxError(Error):
    """A general syntax error for the definition."""


class DefinitionFileTypeError(Error):
    """Invalid Definition File"""


# Consider making this span-oriented
# (file > line > (start_ch, end_ch))
class UserMessage:
    """A user-facing error message encountered during file processing.

    Users can be shown:
    * An error message only (user_message.message).
    * An error message with file / line / include stack (user_message.__repr__()).

    Attributes:
        message: The error message.
        filename: The name of the file in which this error or message originated.
        line: The line where this error or message originated.
        include_chain: If the error or message originated while processing an included
            file, include_chain will list the include file chain as a list of file/line tuples.
            The top-level file should be the first item in the list.
    """

    def __init__(
        self,
        message: str,
        *,
        filename: str,
        line: int = None,
        include_chain: List[Tuple[str, int]] = None,
    ):
        self.message = message
        self.filename = filename
        self.line = line
        self.include_chain = include_chain

    def __str__(self) -> str:
        """Display user-facing error message with include chain (if present).

        e.g.
        Excessive recursion: include depth limit of 5 reached. File=include_1.pol-include.yaml, Line=3.
        Include stack:
        > File='policy_with_include.pol.yaml', Line=11 (Top Level)
        > File='include_1.pol-include.yaml', Line=3
        > File='include_1.pol-include.yaml', Line=3
        > File='include_1.pol-include.yaml', Line=3
        > File='include_1.pol-include.yaml', Line=3
        > File='include_1.pol-include.yaml', Line=3
        """  # noqa: E501
        error_context = f"{self.message} File={self.filename}"
        if self.line is not None:
            error_context += f", Line={self.line}"
        error_context += "."
        if self.include_chain is not None and len(self.include_chain) > 1:
            error_context += "\nInclude stack:"
            for i, (File, Line) in enumerate(self.include_chain):
                error_context += f"\n> File='{File}', Line={Line}"
                if i == 0:
                    error_context += " (Top Level)"
        return error_context

    def __repr__(self) -> str:
        return f"UserMessage(\"{str(self)}\")"


def is_yaml_suffix(suffix: str) -> bool:
    return suffix == '.yaml' or suffix == '.yml'


class _ItemUnit:
    """This class is a container for an index key and a list of associated values.

    An ItemUnit will contain the name of either a service or network group,
    and a list of the associated values separated by spaces.

    Attributes:
      name: A string representing a unique token value.
      items: a list of strings containing values for the token.
    """

    def __init__(
        self,
        symbol: str,
        definition_type: str,
        items: Dict[str, Self],
        unseen_items: Dict[str, Self],
    ) -> None:
        self.name = symbol
        self.items = []
        if symbol in items:
            raise NamespaceCollisionError(
                f'\nMultiple definitions found for {definition_type}: {symbol}'
            )

        items[symbol] = self
        if symbol in unseen_items:
            unseen_items.pop(symbol)

        if not Naming.TOKEN_RE.match(symbol):
            logging.info(
                f'\n{definition_type}: name does not match recommended criteria: {symbol}\nOnly A-Z, a-z, 0-9, -, and _ allowed'
            )


class Naming:
    """Object to hold naming objects from NETWORK and SERVICES definition files.

    Attributes:
       current_symbol: The current token being handled while parsing data.
       services: A collection of all of the current service item tokens.
       networks: A collection of all the current network item tokens.
       unseen_services: Undefined service entries.
       unseen_networks: Undefined network entries.
    """

    TOKEN_RE = re.compile(r'(^[-_A-Z0-9]+$)', re.IGNORECASE)
    PORT_RE = re.compile(r'(^\d+-\d+|^\d+)\/\w+$|^[\w\d-]+$', re.IGNORECASE | re.DOTALL)

    def __init__(
        self, naming_dir: str = None, naming_file: str = None, naming_type: str = None
    ) -> None:
        """Set the default values for a new Naming object.

        Args:
          naming_dir: A string containing a file path to the directory where
            definition files are located.
          naming_file: Optional. A string containing the file path to a specific
            defintion file. Only this file will be loaded if naming_file is given.
          naming_type: Optional. A string containing either 'service' or 'network'.
            This option is only needed if naming_file is provided and it refers to
            a non-YAML file.
        """
        self.current_symbol = None
        self.services = {}
        self.networks = {}
        self.unseen_services = {}
        self.unseen_networks = {}

        if naming_file:
            file_path = Path(naming_dir).joinpath(naming_file)
            if is_yaml_suffix(file_path.suffix):
                if naming_type:
                    logging.warning('Naming object: ignoring unexpected naming_type.')

                with open(file_path, 'r') as file_handle:
                    self.ParseYaml(file_handle, file_path.name)
            elif naming_type:
                with open(file_path, 'r') as file_handle:
                    self._ParseFile(file_handle, naming_type)

        elif naming_dir:
            if naming_type:
                logging.warning('Naming object: ignoring unexpected naming_type.')

            self._Parse(naming_dir)
            self._CheckUnseen()

    def _CheckUnseen(self) -> None:
        if self.unseen_services:
            raise UndefinedServiceError(
                '%s %s'
                % (
                    'The following tokens were nested as a values, but not defined',
                    self.unseen_services,
                )
            )
        if self.unseen_networks:
            raise UndefinedAddressError(
                '%s %s'
                % (
                    'The following tokens were nested as a values, but not defined',
                    self.unseen_networks,
                )
            )

    def GetIpParents(self, query: str) -> List[str]:
        """Return network tokens that contain IP in query.

        Args:
          query: an ip string ('10.1.1.1') or nacaddr.IP object

        Returns:
          A sorted list of unique parent tokens.
        """
        base_parents = []
        recursive_parents = []
        # convert string to nacaddr, if arg is ipaddr then convert str() to nacaddr
        if not isinstance(query, nacaddr.IPv4) and not isinstance(query, nacaddr.IPv6):
            if query[:1].isdigit():
                query = nacaddr.IP(query)
        # Get parent token for an IP
        if isinstance(query, nacaddr.IPv4) or isinstance(query, nacaddr.IPv6):
            for token in self.networks:
                for item in self.networks[token].items:
                    item = item.split('#')[0].strip()
                    if not item[:1].isdigit():
                        continue
                    try:
                        supernet = nacaddr.IP(item, strict=False)
                        if supernet.supernet_of(query):
                            base_parents.append(token)
                    except ValueError:
                        # item was not an IP
                        pass
        # Get parent token for another token
        else:
            for token in self.networks:
                for item in self.networks[token].items:
                    item = item.split('#')[0].strip()
                    if item[:1].isalpha() and item == query:
                        base_parents.append(token)
        # look for nested tokens
        for bp in base_parents:
            done = False
            for token in self.networks:
                if bp in [item.split('#')[0].strip() for item in self.networks[token].items]:
                    # ignore IPs, only look at token values
                    if bp[:1].isalpha():
                        if bp not in recursive_parents:
                            recursive_parents.append(bp)
                            recursive_parents.extend(self.GetIpParents(bp))
                        done = True
            # if no nested tokens, just append value
            if not done:
                if bp[:1].isalpha() and bp not in recursive_parents:
                    recursive_parents.append(bp)
        return sorted(list(set(recursive_parents)))

    def GetServiceParents(self, query: str) -> List[str]:
        """Given a query token, return list of services definitions with that token.

        Args:
          query: a service token name.
        Returns:
          List of service definitions containing the token.
        """
        return self._GetParents(query, self.services)

    def GetNetParents(self, query: str) -> List[str]:
        """Given a query token, return list of network definitions with that token.

        Args:
          query: a network token name.
        Returns:
          A list of network definitions containing the token.
        """
        return self._GetParents(query, self.networks)

    def _GetParents(self, query: str, query_group: Dict[str, _ItemUnit]) -> List[str]:
        """Given a naming item dict, return any tokens containing the value.

        Args:
          query: a service or token name, such as 53/tcp or DNS
          query_group: either services or networks dict

        Returns:
          Returns a list of definitions containing the token in desired group.
        """
        base_parents = []
        recursive_parents = []
        # collect list of tokens containing query
        for token in query_group:
            if query in [item.split('#')[0].strip() for item in query_group[token].items]:
                base_parents.append(token)
        if not base_parents:
            return []
        # iterate through tokens containing query, doing recursion if necessary
        for bp in base_parents:
            for token in query_group:
                if bp in query_group[token].items and bp not in recursive_parents:
                    recursive_parents.append(bp)
                    recursive_parents.extend(self._GetParents(bp, query_group))
            if bp not in recursive_parents:
                recursive_parents.append(bp)
        return recursive_parents

    def GetNetChildren(self, query: str) -> List[str]:
        """Given a query token, return list of network definitions tokens within provided token.

        This will only return children, not descendants of provided token.

        Args:
          query: a network token name.

        Returns:
          A list of network definitions tokens within this token.
        """
        return self._GetChildren(query, self.networks)

    def _GetChildren(self, query: str, query_group: Dict[str, _ItemUnit]) -> List[str]:
        """Given a naming item dict, return tokens (not IPs) contained within this value.

        Args:
          query: a token name
          query_group: networks dict

        Returns:
          Returns a list of definitions tokens within (children) target token.
        """

        children = []
        if query in query_group:
            for item in query_group[query].items:
                child = item.split('#')[0].strip()

                # Determine if item a token, then it's a child
                if not self._IsIpFormat(child):
                    children.append(child)

        return children

    def _IsIpFormat(self, item: str) -> bool:
        """Helper function for _GetChildren to detect if string is IP format.

        Args:
          item: string either a IP or token.
        Returns:
          True if string is a IP
          False if string is not a IP
        """
        try:
            item = item.strip()
            nacaddr.IP(item, strict=False)
            return True
        except ValueError:
            return False

    def GetServiceNames(self) -> List[str]:
        """Returns the list of all known service names."""
        return list(self.services.keys())

    def GetService(self, query: str) -> List[str]:
        """Given a service name, return a list of associated ports and protocols.

        Args:
          query: Service name symbol or token.

        Returns:
          A list of service values such as ['80/tcp', '443/tcp', '161/udp', ...]

        Raises:
          UndefinedServiceError: If the service name isn't defined.
        """
        expandset = set()
        already_done = set()
        data = []
        service_name = ''
        data = query.split('#')  # Get the token keyword and remove any comment
        service_name = data[0].split()[0]  # strip and cast from list to string
        if service_name not in self.services:
            raise UndefinedServiceError('\nNo such service: %s' % query)

        already_done.add(service_name)

        for next_item in self.services[service_name].items:
            # Remove any trailing comment.
            service = next_item.split('#')[0].strip()
            # Recognized token, not a value.
            if '/' not in service:
                # Make sure we are not descending into recursion hell.
                if service not in already_done:
                    already_done.add(service)
                    try:
                        expandset.update(self.GetService(service))
                    except UndefinedServiceError as e:
                        # One of the services in query is undefined, refine the error msg.
                        raise UndefinedServiceError('%s (in %s)' % (e, query))
            else:
                expandset.add(service)
        return sorted(expandset)

    def GetPortParents(self, query: str, proto: str) -> List[str]:
        """Returns a list of all service tokens containing the port/protocol pair.

        Args:
            query: port number ('22') as str
            proto: protocol name ('tcp') as str

        Returns:
            A list of service tokens: ['SSH', 'HTTPS']

        Raises:
          UndefinedPortError: If the port/protocol pair isn't used in any
          service tokens.
        """
        # turn the given port and protocol into a PortProtocolPair object
        given_ppp = portlib.PPP(query + '/' + proto)
        base_parents = []
        matches = set()
        # check each service token to see if it's a PPP or a nested group.
        # if it's a PPP, see if there's a match with given_ppp
        # otherwise, add nested group to a list to recurisvely check later.
        # if there's no match, do nothing.
        for service_token in self.services:
            for port_child in self.services[service_token].items:
                ppp = portlib.PPP(port_child)
                # check for exact match
                if ppp.is_single_port and ppp == given_ppp:
                    matches.add(service_token)
                # check if it's within ppp's port range
                elif ppp.is_range and given_ppp in ppp:
                    matches.add(service_token)
                # if it's a nested token, add to a list to recurisvely
                # check later.
                elif ppp.nested:
                    if service_token not in base_parents:
                        base_parents.append(service_token)
        # break down the nested service tokens into PPP objects and check
        # against given_ppp
        for bp in base_parents:
            for port_child in self.GetService(bp):
                ppp = portlib.PPP(port_child)
                # check for exact match
                if ppp.is_single_port and ppp == given_ppp:
                    matches.add(bp)
                # check if it's within ppp's port range
                elif ppp.is_range and given_ppp in ppp:
                    matches.add(bp)
        # error if the port/protocol pair is not found.
        if not matches:
            raise UndefinedPortError('%s/%s is not found in any service tokens' % (query, proto))
        return sorted(matches)

    def GetServiceByProto(self, query: str, proto: str) -> List[str]:
        """Given a service name, return list of ports in the service by protocol.

        Args:
          query: Service name to lookup.
          proto: A particular protocol to restrict results by, such as 'tcp'.

        Returns:
          A list of service values of type 'proto', such as ['80', '443', ...]

        Raises:
          UndefinedServiceError: If the service name isn't defined.
        """
        services_set = set()
        proto = proto.upper()
        data = []
        servicename = ''
        data = query.split('#')  # Get the token keyword and remove any comment
        servicename = data[0].split()[0]  # strip and cast from list to string
        if servicename not in self.services:
            raise UndefinedServiceError('%s %s' % ('\nNo such service,', servicename))

        for service in self.GetService(servicename):
            if service and '/' in service:
                parts = service.split('/')
                if parts[1].upper() == proto:
                    services_set.add(parts[0])
        return sorted(services_set)

    def GetNetAddr(self, token: str) -> List[Union[IPv4, IPv6]]:
        """Given a network token, return a list of nacaddr.IPv4 or nacaddr.IPv6 objects.

        Args:
          token: A name of a network definition, such as 'INTERNAL'

        Returns:
          A list of nacaddr.IPv4 or nacaddr.IPv6 objects.

        Raises:
          UndefinedAddressError: if the network name isn't defined.
        """
        return self.GetNet(token)

    def GetNet(self, query: str) -> List[Union[IPv4, IPv6]]:
        """Expand a network token into a list of nacaddr.IPv4 or nacaddr.IPv6 objects.

        Args:
          query: Network definition token which may include comment text

        Raises:
          BadNetmaskTypeError: Results when an unknown netmask_type is
          specified.  Acceptable values are 'cidr', 'netmask', and 'hostmask'.

        Returns:
          List of nacaddr.IPv4 or nacaddr.IPv6 objects

        Raises:
          UndefinedAddressError: for an undefined token value
        """
        returnlist = []
        data = []
        token = ''
        data = query.split('#')  # Get the token keyword and remove any comment
        token = data[0].split()[0]  # Remove whitespace and cast from list to string
        if token not in self.networks:
            raise UndefinedAddressError('%s %s' % ('\nUNDEFINED:', str(token)))

        for i in self.networks[token].items:
            comment = ''
            if i.find('#') > -1:
                (net, comment) = i.split('#', 1)
            else:
                net = i

            net = net.strip()
            if self.TOKEN_RE.match(net):
                returnlist.extend(self.GetNet(net))
            else:
                try:
                    # TODO(robankeny): Fix using error to continue processing.
                    addr = nacaddr.IP(net, strict=False)
                    addr.text = comment.lstrip()
                    addr.token = token
                    returnlist.append(addr)
                except ValueError:
                    # if net was something like 'FOO', or the name of another token which
                    # needs to be dereferenced, nacaddr.IP() will return a ValueError
                    returnlist.extend(self.GetNet(net))
        for i in returnlist:
            i.parent_token = token
        return returnlist

    def _Parse(self, definitions_directory: str) -> None:
        """Parse files for tokens and values.

        Given a directory name, grab all the appropriate files in that
        directory and parse them for definitions.

        Args:
          defdirectory: Path to directory containing definition files.
          def_type: Type of definitions to parse

        Raises:
          NoDefinitionsError: if no definitions are found.
        """
        file_def_type = {
            '.net': DEF_TYPE_NETWORKS,
            '.svc': DEF_TYPE_SERVICES,
            '.yaml': 'yaml',
            '.yml': 'yaml',
        }

        for path in Path(definitions_directory).iterdir():

            def_type = file_def_type.get(path.suffix)

            if not def_type:
                continue

            try:
                with open(path, 'r') as file:
                    if def_type == 'yaml':
                        self.ParseYaml(file, path.name)
                    else:
                        self._ParseFile(file, def_type)

            except IOError as error_info:
                raise NoDefinitionsError('%s' % error_info)

    def _ParseFile(self, file_handle: List[str], def_type: str) -> None:
        if def_type == DEF_TYPE_SERVICES:
            items = self.services
            unseen_items = self.unseen_services
            value_check = self._PortCheck
        elif def_type == DEF_TYPE_NETWORKS:
            items = self.networks
            unseen_items = self.unseen_networks
            value_check = None
        else:
            raise UnexpectedDefinitionTypeError(
                '%s %s' % ('Received an unexpected definition type:', def_type)
            )

        generator = self._ParseLines(file_handle, def_type, items, unseen_items, value_check)
        items.update(dict([(unit.name, unit) for unit in generator]))

    def ParseServiceList(self, data: List[str]) -> None:
        """Take an array of service data and import into class.

        This method allows us to pass an array of data that contains service
        definitions that are appended to any definitions read from files.

        Args:
          data: array of text lines containing service definitions.
        """
        generator = self._ParseLines(
            data,
            DEF_TYPE_SERVICES,
            self.services,
            self.unseen_services,
            self._PortCheck,
        )
        self.services.update(dict([(unit.name, unit) for unit in generator]))

    def ParseNetworkList(self, data: List[str]) -> None:
        """Take an array of network data and import into class.

        This method allows us to pass an array of data that contains network
        definitions that are appended to any definitions read from files.

        Args:
          data: array of text lines containing net definitions.

        """
        generator = self._ParseLines(data, DEF_TYPE_NETWORKS, self.networks, self.unseen_networks)
        self.networks.update(dict([(unit.name, unit) for unit in generator]))

    def _PortCheck(self, line: str, values: str) -> None:
        for port in values.strip().split():
            if not self.PORT_RE.match(port):
                raise NamingSyntaxError('%s: %s' % ('The following line has a syntax error', line))

    def _ParseLines(
        self,
        data: Iterable,
        def_type: str,
        items: Dict[str, _ItemUnit],
        unseen_items: Dict[str, Union[_ItemUnit | bool]],
        value_check: Callable[[str, str], None] = None,
    ) -> None:
        unit = None
        current_symbol = None

        for line in data:
            line = line.strip()
            if not line or line.startswith('#'):  # Skip comments and blanks.
                continue
            comment = ''
            if line.find('#') > -1:  # if there is a comment, save it
                (line, comment) = line.split('#', 1)
            line_parts = line.split('=')  # Split on var = val lines.
            # the value field still has the comment at this point
            # If there was '=', then do var and value
            if len(line_parts) > 1:
                if unit:
                    yield unit

                current_symbol = line_parts[0].strip()  # varname left of '='

                if value_check:
                    value_check(line, line_parts[1])

                unit = _ItemUnit(current_symbol, def_type, items, unseen_items)
                values = line_parts[1]
            # No '=', so this is a value only line
            else:
                if value_check:
                    value_check(line, line_parts[0])
                values = line_parts[0]  # values for previous var are continued this line

            for value_piece in values.split():
                if not value_piece:
                    continue
                if not current_symbol:
                    break
                if comment:
                    unit.items.append(value_piece + ' # ' + comment)
                else:
                    unit.items.append(value_piece)
                    # token?
                    if value_piece[0].isalpha() and ':' not in value_piece:
                        if value_piece not in items and value_piece not in unseen_items:
                            unseen_items[value_piece] = True

    def ParseYaml(self, file_handle: str, file_name: str) -> None:
        """Load a definition yaml file as a string.

        Arguments:
            file: A string containing the file contents.
            filename: The original filename of the file.
        """

        try:
            file_data = yaml.load(file_handle, Loader=SpanSafeYamlLoader(filename=file_name))
        except YAMLError as yaml_error:
            raise DefinitionFileTypeError(
                UserMessage("Unable to read file as YAML.", filename=file_name)
            ) from yaml_error

        self.ParseDefinitionsObject(file_data, file_name)

    def ParseDefinitionsObject(self, file_data: Dict[str, str], file_name: str) -> None:
        # Empty files are ignored with a warning
        if not file_data:
            logging.warning(UserMessage("Ignoring empty address book file.", filename=file_name))
            return

        # Check for at least one essential key, ignore with warning
        essential_keys = ['networks', 'services']

        if not any((key in file_data for key in essential_keys)):
            logging.warning(
                UserMessage("File contains no network or service data.", filename=file_name)
            )
            return

        if 'networks' in file_data:
            self._ParseYamlNetworks(file_data, file_name)

        if 'services' in file_data:
            self._ParseYamlServices(file_data, file_name)

    def _ParseYamlNetworks(self, file_data: Dict[str, Any], file_name: str) -> None:
        if 'networks' in file_data and not isinstance(file_data['networks'], dict):
            logging.warning(
                UserMessage(
                    "Network definition type error: dictionary expected.", filename=file_name
                )
            )
            return

        # Construct ItemUnit for each data point
        for symbol, symbol_def in file_data['networks'].items():
            if symbol in ["__line__", "__filename__"]:
                continue

            if not ('values' in symbol_def and isinstance(symbol_def['values'], list)):
                logging.info(
                    f'\nNetwork definition must be a list. Ignoring definition for network: {symbol}.'
                )
                continue

            unit = _ItemUnit(symbol, DEF_TYPE_NETWORKS, self.networks, self.unseen_networks)

            for item in symbol_def['values']:
                # 'item' can be:
                # 1. A string, understood as a network name reference
                # 2. A dictionary, with these fields:
                #    'address': A specific IP address or CIDR range
                #    'name': A network name reference
                #    'comment': An optional comment
                # 'address' or 'name' must be present in any dictionary item
                value = None
                network_ref = None
                ip = None
                comment = None
                if isinstance(item, str):
                    value = network_ref = item
                elif isinstance(item, dict):
                    if 'name' in item and isinstance(item['name'], str):
                        value = network_ref = item['name']
                    elif 'address' in item and isinstance(item['address'], str):
                        value = ip = item['address']
                    else:
                        logging.info(f'\nNetwork name or CIDR expected for: {symbol}')
                        continue

                    if 'comment' in item and isinstance(item['comment'], str):
                        comment = item['comment']
                else:
                    logging.info(f'\nUnexpected symbol definition: {symbol}')
                    continue

                if comment is None:
                    unit.items.append(value)
                else:
                    unit.items.append(f'{value} # {comment}')

                if network_ref and network_ref not in self.networks:
                    if network_ref not in self.unseen_networks:
                        self.unseen_networks[network_ref] = True

    def _ParseYamlServices(self, file_data: Dict[str, Any], file_name: str) -> None:
        if 'services' in file_data and not isinstance(file_data['services'], dict):
            logging.warning(
                UserMessage(
                    "Service definition type error: dictionary expected.", filename=file_name
                )
            )
            return

        # Construct ItemUnit for each data point
        for symbol, symbol_def in file_data['services'].items():
            if symbol in ["__line__", "__filename__"]:
                continue

            if not isinstance(symbol_def, list):
                logging.info(
                    f'\nService definition must be a list. Ignoring definition for service: {symbol}.'
                )
                continue

            unit = _ItemUnit(symbol, DEF_TYPE_SERVICES, self.services, self.unseen_services)

            for item in symbol_def:
                # 'item' can be:
                # 1. A string, understood as a service name reference
                # 2. A dictionary, with these fields:
                #    'protocol': A logical or numeric protocol (e.g. 'tcp')
                #    'port': A port number
                #    'name': A service name reference
                #    'comment': An optional comment
                # ('protocol' and 'port') or 'name' must be present in any dictionary item
                value = None
                service_ref = None
                service_port = None
                comment = None
                if isinstance(item, str):
                    value = service_ref = item
                elif isinstance(item, dict):
                    if 'name' in item and isinstance(item['name'], str):
                        value = service_ref = item['name']
                    elif (
                        'port' in item
                        and (isinstance(item['port'], str) or isinstance(item['port'], int))
                        and 'protocol' in item
                        and (
                            isinstance(item['protocol'], str) or isinstance(item['protocol'], int)
                        )
                    ):
                        protocol = item['protocol']
                        port = item['port']
                        value = service_port = f'{port}/{protocol}'
                    else:
                        logging.info(f'\nService name or port definition expected for: {symbol}')
                        continue
                    if 'comment' in item and isinstance(item['comment'], str):
                        comment = item['comment']
                else:
                    logging.info(f'\nUnexpected symbol definition: {symbol}')
                    continue

                if comment is None:
                    unit.items.append(value)
                else:
                    unit.items.append(f'{value} # {comment}')

                if service_ref and service_ref not in self.services:
                    if service_ref not in self.unseen_services:
                        self.unseen_services[service_ref] = True
