from unittest import mock

from absl.testing import absltest

from aerleon.lib.cisco import Cisco
from aerleon.lib.juniper import Juniper
from aerleon.lib.plugin_supervisor import (
    _PluginSupervisor,
    PluginSupervisorConfiguration,
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
        self.PluginSupervisor = _PluginSupervisor()
        self.PluginSupervisor.Start()

        self.assertEquals(self.PluginSupervisor.plugins, [])
        self.assertEquals(self.PluginSupervisor.generators["cisco"], Cisco)
        self.assertEquals(self.PluginSupervisor.generators["juniper"], Juniper)
        self.mock_entry_points.assert_called_once()

    def testPluginSupervisorConfigDisableDiscovery(self):
        self.mock_entry_points.return_value = []
        self.PluginSupervisor = _PluginSupervisor()
        self.PluginSupervisor.Start(PluginSupervisorConfiguration(disable_discovery=True))

        self.assertEquals(self.PluginSupervisor.plugins, [])
        self.assertEquals(self.PluginSupervisor.generators["cisco"], Cisco)
        self.assertEquals(self.PluginSupervisor.generators["juniper"], Juniper)
        self.mock_entry_points.assert_not_called()

    def testPluginSupervisorConfigDisableBuiltin(self):
        self.PluginSupervisor = _PluginSupervisor()
        self.PluginSupervisor.Start(
            PluginSupervisorConfiguration(disable_discovery=True, disable_builtin=['cisco'])
        )

        self.assertEquals(self.PluginSupervisor.plugins, [])
        self.assertEquals(self.PluginSupervisor.generators.get("cisco", None), None)
        self.assertEquals(self.PluginSupervisor.generators["juniper"], Juniper)

    def testPluginSupervisorConfigDisableBuiltin(self):
        self.PluginSupervisor = _PluginSupervisor()
        self.PluginSupervisor.Start(
            PluginSupervisorConfiguration(disable_discovery=True, disable_builtin=['cisco'])
        )

        self.assertEquals(self.PluginSupervisor.plugins, [])
        self.assertEquals(self.PluginSupervisor.generators.get("cisco", None), None)
        self.assertEquals(self.PluginSupervisor.generators["juniper"], Juniper)

if __name__ == '__main__':
    absltest.main()
