# Copyright (c) 2017 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.plugins.windows.updates"


class WindowsAutoUpdatesPluginTest(unittest.TestCase):

    def setUp(self):
        self.mock_win32com = mock.MagicMock()
        patcher = mock.patch.dict(
            "sys.modules",
            {
                "win32com": self.mock_win32com
            }
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        updates = importlib.import_module(MODPATH)
        self._updates_plugin = updates.WindowsAutoUpdatesPlugin()
        self.snatcher = testutils.LogSnatcher(MODPATH)

    @testutils.ConfPatcher("enable_automatic_updates", True)
    @mock.patch("cloudbaseinit.utils.windows.updates.set_automatic_updates")
    def test_execute(self, mock_set_updates):
        mock_service = mock.Mock()
        mock_shared_data = mock.Mock()
        mock_service.get_enable_automatic_updates.return_value = True

        expected_res = (base.PLUGIN_EXECUTION_DONE, False)
        expected_logs = ["Configuring automatic updates: %s" % True]
        with self.snatcher:
            res = self._updates_plugin.execute(mock_service, mock_shared_data)
        self.assertEqual(res, expected_res)
        self.assertEqual(self.snatcher.output, expected_logs)
        mock_service.get_enable_automatic_updates.assert_called_once_with()
        mock_set_updates.assert_called_once_with(True)

    def test_get_os_requirements(self):
        expected_res = ('win32', (5, 2))
        requirements_res = self._updates_plugin.get_os_requirements()
        self.assertEqual(requirements_res, expected_res)
