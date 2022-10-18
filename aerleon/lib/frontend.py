"""Intermediate data models and classes for the front-end parsing phase.

Classes:

## RawPolicy, RawFilter, RawTerm, RawKV

These classes act as an intermediate representation between a raw file representation
and the main data models (Policy, Naming). They exist mainly to support the consultative
extension system (consulting the generators during the parse process through the hooks
RecognizeKeyword(), RecognizeKeywordValue()).

## ConsultativePolicyBuilder

This class executes the consultative parse process. It transforms RawPolicy into Policy
by consulting all loaded generators (through the hooks RecognizeKeyword(),
RecognizeKeywordValue()) to understand what keywords are considered valid and what options
are valid.
"""

from dataclasses import dataclass
import typing

from aerleon.lib import models


@dataclass
class RawKV:
    keyname: str
    value: typing.Any


@dataclass
class RawTarget:
    target: typing.Any


@dataclass
class RawFilterHeader:
    targets: list[RawTarget]
    kvs: list[RawKV]


@dataclass
class RawTerm:
    name: str
    kvs: list[RawKV]


@dataclass
class RawFilter:
    header: RawFilterHeader
    terms: list[RawTerm]


@dataclass
class RawPolicy:
    filename: str
    filters: list[RawFilter]


class ConsultativePolicyBuilder:
    """
    This class executes the consultative parse process. It transforms RawPolicy into Policy
    by consulting all loaded generators (through the hooks RecognizeKeyword(),
    RecognizeKeywordValue()) to understand what keywords are considered valid and what options
    are valid.

    Usage:

    config = {
        generatorTable: generatorTable
    }
    policy_builder = ConsultativePolicyBuilder(**config)

    policy = policy_builder.raw_to_policy(raw_policy)

    Strategy:


    """

    def __init__(self):
        pass

    def raw_to_policy(self, raw_policy):
        """Build a Policy model from a RawPolicy using the consultative extension system.

        See description in ConsultativePolicyBuilder for more details.
        """
        return models.Policy()
