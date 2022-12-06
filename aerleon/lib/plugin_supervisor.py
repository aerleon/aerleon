"""Plugin Supervisor.

## Configuring the Plug-in Supervisor

PluginSupervisor.Start() will by default search for and load any installed
packages with a plugin entrypoint matching "aerleon.plugin".

## Plugin Lifecycle

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

from dataclasses import dataclass
from importlib import import_module
import importlib.util
import pathlib
import sys
from typing import Annotated, Tuple

if sys.version_info < (3, 10):
    from importlib_metadata import entry_points, version
else:
    from importlib.metadata import entry_points, version

from absl import logging

from aerleon.lib import plugin

__all__ = ["PluginSupervisor", "PluginSupervisorConfiguration", "SystemMetadata"]


class _PluginSupervisor:
    is_setup: bool
    plugins: list[Tuple]
    generators: dict

    def __init__(self):
        self.is_setup = False

    def Start(self, config: PluginSupervisorConfiguration = None):
        setup = _PluginSetup(config)
        self.plugins, self.generators = setup.plugins, setup.generators
        self.is_setup = True


__doc_PluginSupervisor__ = """Singleton PluginSupervisor instance."""
PluginSupervisor = _PluginSupervisor()


@dataclass
class SystemMetadata:
    engine_version: str


__doc_SYSTEM_METADATA__ = """Public module constant system metadata."""
SYSTEM_METADATA: SystemMetadata = SystemMetadata(engine_version=version("aerleon"))

__doc_BUILTIN_PLUGINS__ = (
    """Built-in plugins included with this project. These will always be loaded.""",
)
BUILTIN_GENERATORS: list[Tuple] = [
    # fmt: off
    #Target                  Module                              Constructor
    ('juniper',              'aerleon.lib.juniper',              'Juniper'),
    ('juniperevo',           'aerleon.lib.juniperevo',           'JuniperEvo'),
    ('msmpc',                'aerleon.lib.junipermsmpc',         'JuniperMSMPC'),
    ('srx',                  'aerleon.lib.junipersrx',           'JuniperSRX'),
    ('cisco',                'aerleon.lib.cisco',                'Cisco'),
    ('ciscoasa',             'aerleon.lib.ciscoasa',             'CiscoASA'),
    ('aruba',                'aerleon.lib.aruba',                'Aruba'),
    ('brocade',              'aerleon.lib.brocade',              'Brocade'),
    ('arista',               'aerleon.lib.arista',               'Arista'),
    ('arista_tp',            'aerleon.lib.arista_tp',            'AristaTrafficPolicy'),
    ('ipset',                'aerleon.lib.ipset',                'Ipset'),
    ('iptables',             'aerleon.lib.iptables',             'Iptables'),
    ('nsxv',                 'aerleon.lib.nsxv',                 'Nsxv'),
    ('openconfig',           'aerleon.lib.openconfig',           'OpenConfig'),
    ('speedway',             'aerleon.lib.speedway',             'Speedway'),
    ('pcap',                 'aerleon.lib.pcap',                 'PcapFilter'),
    ('pcap',                 'aerleon.lib.pcap',                 'PcapFilter'),
    ('packetfilter',         'aerleon.lib.packetfilter',         'PacketFilter'),
    ('windows_advfirewall',  'aerleon.lib.windows_advfirewall',  'WindowsAdvFirewall'),
    ('srxlo',                'aerleon.lib.srxlo',                'SRXlo'),
    ('cisconx',              'aerleon.lib.cisconx',              'CiscoNX'),
    ('ciscoxr',              'aerleon.lib.ciscoxr',              'CiscoXR'),
    ('nftables',             'aerleon.lib.nftables',             'Nftables'),
    ('gce',                  'aerleon.lib.gce',                  'GCE'),
    ('gcp_hf',               'aerleon.lib.gcp_hf',               'HierarchicalFirewall'),
    ('paloalto',             'aerleon.lib.paloaltofw',           'PaloAltoFW'),
    ('cloudarmor',           'aerleon.lib.cloudarmor',           'CloudArmor'),
    ('k8s',                  'aerleon.lib.k8s',                  'K8s'),
    # fmt: on
]


class PluginSetupCollisionError(Exception):
    """A plugin was already loaded for the same firewall platform."""


@dataclass
class PluginSupervisorConfiguration:
    """
    Attributes:
        disable_discovery: Plugin discovery via pip will not be performed if True. Consider
            this setting if plugin discovery is not needed and problematic modules are present
            in this pip installation or discovery is taking a long time.

        disable_plugin: A list of discovered plugins to ignore, given by plugin name. Consider
            this setting if one or more specific plugins are causing problems.

        disable_builtin: A list of built-in generators to ignore, given by module name (e.g.
            'juniper'). Use this setting if you plan to use an alternative generator for
            a firewall platform with built-in support.

        include_path: A list of plug-ins to include, given by package name. Through this
            option, plug-in packages can be included if they are present in the same
            Python installation but not registered through the normal Python plugin
            entrypoint system. Plug-ins included this way are expeted to implement a
            top-level function called "AerleonPlugin" that returns an instance of
            aerleon.lib.Plugin .
    """

    disable_discovery: bool = False
    disable_plugin: list[str] = None
    disable_builtin: list[str] = None
    include_path: list[list[str]] = None


class _PluginSetup:
    """
    Discover, load, interrogate and initialize all available plugins.

    Attributes:
        generators: All generators loaded from plugins.
        plugins: All loaded plugins.
        disable_discovery: See PluginSupervisorConfiguration.
        disable_plugin: See PluginSupervisorConfiguration.
        disable_builtin: See PluginSupervisorConfiguration.
        include_path: See PluginSupervisorConfiguration.
    """

    disable_discovery: bool = False
    disable_plugin: list[str] = None
    disable_builtin: list[str] = None
    include_path: list[list[str]] = None
    
    generators = {}
    plugins = []

    def __init__(self, config: PluginSupervisorConfiguration = None):
        """Initialize self.generators, self.plugins."""

        # Apply configuration if provided
        if config is not None:
            self.disable_discovery = getattr(config, 'disable_discovery', False)
            self.disable_plugin = getattr(config, 'disable_plugin', None)
            self.disable_builtin = getattr(config, 'disable_builtin', None)
            self.include_path = getattr(config, 'include_path', None)

        # Initialize generator list with built-in generators
        self.generators.update(self._CollectBuiltinGenerators(BUILTIN_GENERATORS))

        # Collect plugins from various sources
        loaded_plugins = []
        if not self.disable_discovery:
            loaded_plugins.extend(self._CollectEntrypointPlugins())
        if self.include_path:
            loaded_plugins.extend(self._CollectPluginsByPath())

        # Attempt to load, initialize, interrogate, and register generators from each plugin
        for plugin_name, loaded_plugin in loaded_plugins:

            # Initialize entrypoint class or function and request metadata
            try:
                plugin_instance: plugin.BasePlugin = loaded_plugin()
                metadata = plugin_instance.RequestMetadata(SYSTEM_METADATA)
                if not isinstance(metadata, plugin.PluginMetadata) or any(
                    filter(
                        lambda c: not isinstance(c, plugin.PluginCapability), metadata.capabilities
                    )
                ):
                    logging.warning(
                        f"Ignoring plugin {plugin_name=}: unrecognized plugin metadata format. {SYSTEM_METADATA.engine_version=}"  # noqa E501
                    )
                    continue
                self.plugins.append((loaded_plugin, metadata))
            except plugin.PluginCompatibilityError as exception:
                logging.warning(
                    f"Ignoring plugin {plugin_name=}: Aerleon version not supported by plugin. {SYSTEM_METADATA.engine_version=}",  # noqa E501
                    exc_info=exception,
                )
                continue

            # Register generators
            if plugin.PluginCapability.GENERATOR not in metadata.capabilities:
                logging.warning(
                    f"Ignoring plugin {plugin_name=}: GENERATOR capability not found. {SYSTEM_METADATA.engine_version=}"  # noqa E501
                )
                continue

            try:
                plugin_generator_items = plugin_instance.generators
            except Exception as exception:
                logging.warning(
                    f"Plugin {plugin_name=} crashed while registering generator.",
                    exc_info=exception,
                )
                continue

            for target, constructor in plugin_generator_items.items():
                found = self.generators.setdefault(target, constructor)
                if found != constructor:
                    # collision: two plugins claim to provide support for the same platform
                    raise PluginSetupCollisionError(
                        f"Plugin misconfiguration: more than one plugin is installed for {target=}. Plugin 1: {found}. Plugin 2: {constructor}."  # noqa E501
                    )

        logging.info(f"{len(self.plugins)} plugins active.")
        logging.info(f"{len(self.generators)} generators registered.")

    def _CollectEntrypointPlugins(self):
        """Locate and import modules using entrypoint discovery."""
        loaded_plugins = []
        for ep_plugin in entry_points(group='aerleon.plugin'):
            if self.disable_plugin and ep_plugin.name in self.disable_plugin:
                continue
            try:
                loaded_plugins.append((ep_plugin.name, ep_plugin.load()))
            except Exception as exception:
                logging.warning(f"Failed to load plugin {ep_plugin.name=}", exc_info=exception)
                continue
        return loaded_plugins

    def _CollectPluginsByPath(self):
        """Import modules given by file path."""
        loaded_plugins = []
        for module_name, file_path, klass_or_func in self.include_path:
            try:
                file_path = pathlib.Path(file_path)
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                loaded_plugins.append((module_name, getattr(module, klass_or_func)))
            except Exception as exception:
                logging.warning(
                    f"Failed to load plugin module={module_name}, class={klass_or_func} at {file_path=}",
                    exc_info=exception,
                )
                continue
        return loaded_plugins

    def _CollectBuiltinGenerators(self, builtin_generators):
        """Import built-in modules by name."""
        loaded_generators = []
        for target, module_name, klass_or_func in builtin_generators:
            if self.disable_builtin and (module_name in self.disable_builtin or target in self.disable_builtin):
                continue
            try:
                module = import_module(module_name)
                loaded_generators.append((target, getattr(module, klass_or_func)))
            except Exception as exception:
                logging.warning(
                    f"Failed to load built-in generator module={module_name}, class={klass_or_func}",
                    exc_info=exception,
                )
                continue
        return loaded_generators
