# Copyright 2020-2021 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
"""A module of utilities to work with IP addresses in a faster way."""

import ipaddress
from collections.abc import Iterator
from typing import Union


def exclude_address(
    base_net: ipaddress._BaseNetwork,  # pylint disable=protected-access
    exclude_net: ipaddress._BaseNetwork,  # pylint disable=protected-access
) -> Iterator[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Function to exclude a subnetwork from another, returning a generator that
    yields all values that correspond to the base network without the exclude
    network.

    This is functionally equivalent to the _BaseNetwork "address_exclude" from the
    `ipaddress` standard library, but is a faster implementation since
    the standard library function is a O(n) operation on the length of the
    netmask of the excluding network, whereas this function is O(1) for all cases.

    Args:
      base_net: an object of type _BaseNetwork, the network that
                contains the exclude network
      exclude_net: an object of type _BaseNetwork, the network
                   that is being removed from the base_net
    Raises:
      ValueError if exclude_net is not completely contained in base_net

    Yields:
      A sequence of IP networks that do not encompass the exclude_net
    """

    if not isinstance(base_net, ipaddress._BaseNetwork):  # pylint disable=protected-access
        raise TypeError(f'{base_net} is not a network object')

    if not isinstance(exclude_net, ipaddress._BaseNetwork):  # pylint disable=protected-access
        raise TypeError(f'{exclude_net} is not a network object')

    if (
        not base_net._version == exclude_net._version
    ):  # pylint disable=protected-access # pytype: disable=attribute-error
        raise TypeError(f'{base_net} and {exclude_net} are not of the same version')

    if not exclude_net.subnet_of(base_net):  # pytype: disable=attribute-error
        raise ValueError()
    if exclude_net == base_net:
        return

    include_range = (
        base_net.network_address._ip,
        base_net.broadcast_address._ip,
    )  # pylint disable=protected-access # pytype: disable=attribute-error
    exclude_range = (
        exclude_net.network_address._ip,
        exclude_net.broadcast_address._ip,
    )  # pylint disable=protected-access # pytype: disable=attribute-error
    address_class = base_net.network_address.__class__  # pylint disable=protected-access
    if include_range[0] == exclude_range[0]:
        result_start = address_class(exclude_range[1] + 1)
        result_end = address_class(include_range[1])
        yield from ipaddress.summarize_address_range(result_start, result_end)
    elif include_range[1] == exclude_range[1]:
        result_start = address_class(include_range[0])
        result_end = address_class(exclude_range[0] - 1)
        yield from ipaddress.summarize_address_range(result_start, result_end)
    else:
        first_section_start = address_class(include_range[0])
        first_section_end = address_class(exclude_range[0] - 1)
        second_section_start = address_class(exclude_range[1] + 1)
        second_section_end = address_class(include_range[1])
        yield from ipaddress.summarize_address_range(first_section_start, first_section_end)
        yield from ipaddress.summarize_address_range(second_section_start, second_section_end)
