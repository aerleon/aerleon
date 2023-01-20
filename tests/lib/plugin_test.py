from unittest import mock

from absl.testing import absltest

from aerleon.lib.cisco import Cisco
from aerleon.lib.juniper import Juniper
from aerleon.lib.plugin_supervisor import (
    PluginSupervisorConfiguration,
    _PluginSupervisor,
)


class PluginSupervisorTest(absltest.TestCase):
    """Test PluginSupervisor class."""

    def setUp(self):
        super().setUp()
        self.mock_entry_points = mock.MagicMock()
        self.mock_entry_points.return_value = []
        self.patchers = [
            mock.patch('aerleon.lib.plugin_supervisor.entry_points', self.mock_entry_points)
        ]
        [patcher.start() for patcher in self.patchers]

    def tearDown(self):
        [patcher.stop() for patcher in self.patchers]

    def testPluginSupervisorSetup(self):
        self.mock_entry_points.return_value = []

        pluginSupervisor = _PluginSupervisor()
        pluginSupervisor.Start()

        self.assertEqual(pluginSupervisor.plugins, [])
        self.assertEqual(pluginSupervisor.generators["cisco"], Cisco)
        self.assertEqual(pluginSupervisor.generators["juniper"], Juniper)
        self.mock_entry_points.assert_called_once()

    def testPluginSupervisorConfigDisableDiscovery(self):
        self.mock_entry_points.return_value = []
        pluginSupervisor = _PluginSupervisor()
        pluginSupervisor.Start(PluginSupervisorConfiguration(disable_discovery=True))

        self.assertEqual(pluginSupervisor.plugins, [])
        self.assertEqual(pluginSupervisor.generators["cisco"], Cisco)
        self.assertEqual(pluginSupervisor.generators["juniper"], Juniper)
        self.mock_entry_points.assert_not_called()

    def testPluginSupervisorConfigDisableBuiltin(self):
        pluginSupervisor = _PluginSupervisor()

        pluginSupervisor.Start(
            PluginSupervisorConfiguration(disable_discovery=True, disable_builtin=['cisco'])
        )

        self.assertEqual(pluginSupervisor.plugins, [])
        self.assertEqual(pluginSupervisor.generators.get("cisco", None), None)
        self.assertEqual(pluginSupervisor.generators["juniper"], Juniper)


if __name__ == '__main__':
    absltest.main()
