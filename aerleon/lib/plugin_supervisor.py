"""Plug-in Supervisor.

## Configuring the Plug-in Supervisor

PluginSupervisor.initPlugins will by default search for and load any installed
packages with a plug-in entrypoint matching "aerleon.plugin". It can be
configured with the following options:

    ignore - a list of plug-ins to ignore, given by package name.
    include - a list of plug-ins to include, given by package name. Through this
        option, plug-in packages can be included if they are present in the same
        Python installation but not registered through the normal Python plugin
        entrypoint system. Plug-ins included this way are expeted to implement a
        top-level function called "AerleonPlugin" that returns an instance of
        aerleon.lib.Plugin .

## Plug-in Lifecycle

Aerleon does "interrogate" each plug-in on start-up. During the interrogation
process, Aerleon determines:
* Whether this plug-in is compatible with the current version of Aerleon.
* What type of plug-in this is.
Aerleon also gives the plug-in an opportunity to detect an incompatible version
(the plug-in author may have more specific information about what Aerleon
versions it can support).

Incompatible plug-ins will be ignored with a warning.

All compatible plug-ins are then asked for internal resources which are
registered to internal tables. For Generator plug-ins, each plug-in is
asked for a table mapping a target name (e.g. "iptables") to a provided
class constructor. Aerleon will consult these mapping tables later during
run time.

For Generator classes, Aerleon will initialize these classes as needed.
The interface between Aerleon and Generator classes is not part of the
plug-in lifecycle or the PluginSupervisor's function.

## Authoring Plug-ins

Plug-in authors should consult the docstring for plugin.py. This file provides
documentation of the requirements for plug-ins as well as a suggested base
class for any Aerleon plug-in to use (BasePlugin).

## Debugging

Plug-in authors may observe that this module exposes its internal state
directly on the module for transparency. These names should be treated as
undocumented and subject to change.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import sys
from typing import Annotated, Tuple

if sys.version_info < (3, 10):
    from importlib_metadata import entry_points, version
else:
    from importlib.metadata import entry_points, version

from absl import logging

from aerleon.lib import plugin


@dataclass
class SystemMetadata:
    engine_version: str


SYSTEM_METADATA: SystemMetadata = Annotated[
    SystemMetadata(engine_version=version("aerleon")),
    """Public module constant system metadata.""",
]

# TODO just use a single list with state vars
SYSTEM_PLUGINS: list[Tuple] = list()

_plugins_loaded = list()
_plugins_active = list()
_plugins_inactive = list()

_generator_table = OrderedDict()


class PluginSetupCollisionError(Exception):
    """A plugin was already loaded for the same firewall platform."""


@dataclass
class PluginSupervisorConfiguration:
    """
    ignore - a list of plug-ins to ignore, given by package name.
    include - a list of plug-ins to include, given by package name. Through this
        option, plug-in packages can be included if they are present in the same
        Python installation but not registered through the normal Python plugin
        entrypoint system. Plug-ins included this way are expeted to implement a
        top-level function called "AerleonPlugin" that returns an instance of
        aerleon.lib.Plugin .
    """

    ignore: list[str] = None
    include: list[str] = None


def initPlugins(config: PluginSupervisorConfiguration = None):
    """
    Discover, load, interrogate and initialize all available plugins.

    config - an instance of PluginSupervisorConfiguration.
    """
    config_ignore = None
    config_include = None
    if config is not None:
        if config.ignore is not None:
            config_ignore = config.ignore
        if config.include is not None:
            config_include = config.include

    ep_plugins = entry_points(group='aerleon.plugin')
    # TODO(jb) implement config_include, find a way to extend the EntryPoints list

    for ep_plugin in ep_plugins:
        if config_ignore is not None and ep_plugin.name in config_ignore:
            continue

        try:
            loaded_plugin = ep_plugin.load()
            _plugins_loaded.append(loaded_plugin)
            plugin_instance = loaded_plugin()
            metadata = plugin_instance.getMetadata(SYSTEM_METADATA)
        except plugin.PluginCompatibilityError as exception:
            logging.warning(
                f"Ignoring plugin {ep_plugin.name=}: Aerleon version not supported by plugin. {SYSTEM_METADATA.engine_version=}",  # noqa E501
                exc_info=exception,
            )
            _plugins_inactive.append((ep_plugin, exception))
            continue
        except Exception as exception:
            logging.warning(f"Failed to load plugin {ep_plugin.name=}", exc_info=exception)
            _plugins_inactive.append((ep_plugin, exception))
            continue

        if not isinstance(metadata, plugin.PluginMetadata) or any(
            filter(lambda c: not isinstance(c, plugin.PluginCapability), metadata.capabilities)
        ):
            logging.warning(
                f"Ignoring plugin {ep_plugin.name=}: non-compliant plugin. {SYSTEM_METADATA.engine_version=}"  # noqa E501
            )

        if plugin.PluginCapability.GENERATOR not in metadata.capabilities:
            continue

        try:
            plugin_generator_items = plugin_instance.generators.items()
        except Exception as exception:
            logging.warning(
                f"Ignoring plugin {ep_plugin.name=}: crashed during setup", exc_info=exception
            )
            continue
        _plugins_active.append((ep_plugin, metadata))

        for target, constructor in plugin_generator_items:
            target_generator = _generator_table.setdefault(target, constructor)
            if target_generator != constructor:
                # collision: two plugins claim to provide support for the same platform
                raise PluginSetupCollisionError(
                    f"Plugin misconfiguration: more than one plugin is installed for {target=}. Plugin 1: {target_generator}. Plugin 2: {constructor}."  # noqa E501
                )

    logging.info(f"{len(_plugins_active)} plugins active.")


def getGenerator(target):
    """Locates the generator that supports the target platform."""
    return _generator_table[target]


def getGenerators():
    """Return all loaded generators"""
    return _generator_table