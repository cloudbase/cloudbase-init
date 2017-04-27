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
from cloudbaseinit import constant
from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.plugins.windows.bootconfig"


class BootConfigPluginTest(unittest.TestCase):

    def setUp(self):
        self.mock_wmi = mock.MagicMock()
        self._moves_mock = mock.MagicMock()
        patcher = mock.patch.dict(
            "sys.modules",
            {
                "wmi": self.mock_wmi,
                "six.moves": self._moves_mock,
                'ctypes': mock.MagicMock(),
                'ctypes.windll': mock.MagicMock(),
                'ctypes.wintypes': mock.MagicMock(),
                'winioctlcon': mock.MagicMock()
            }
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        bootconfig = importlib.import_module(MODPATH)
        self.boot_policy_plugin = bootconfig.BootStatusPolicyPlugin()
        self.bcd_config = bootconfig.BCDConfigPlugin()
        self.snatcher = testutils.LogSnatcher(MODPATH)

    @testutils.ConfPatcher("bcd_boot_status_policy",
                           constant.POLICY_IGNORE_ALL_FAILURES)
    @mock.patch("cloudbaseinit.utils.windows.bootconfig."
                "set_boot_status_policy")
    def _test_execute_policy_plugin(self, mock_set_boot_status_policy,
                                    mock_service=None, mock_shared_data=None):
        expected_res = (base.PLUGIN_EXECUTION_DONE, False)
        expected_logs = [
            "Configuring boot status policy: %s" % CONF.bcd_boot_status_policy]
        with self.snatcher:
            res = self.boot_policy_plugin.execute(mock_service,
                                                  mock_shared_data)
        self.assertEqual(res, expected_res)
        self.assertEqual(self.snatcher.output, expected_logs)
        mock_set_boot_status_policy.assert_called_once_with(
            CONF.bcd_boot_status_policy)

    def test_execute_set_bootstatus_policy(self):
        self._test_execute_policy_plugin()

    @mock.patch("cloudbaseinit.utils.windows.disk.Disk")
    def test_set_unique_disk_id(self, mock_disk):
        fake_disk_path = mock.sentinel.path
        mock_physical_disk = mock.MagicMock()
        expected_logs = ["Setting unique id on disk: %s" % fake_disk_path]
        mock_disk.__enter__.return_value = mock_physical_disk
        with self.snatcher:
            self.bcd_config._set_unique_disk_id(fake_disk_path)
        self.assertEqual(self.snatcher.output, expected_logs)
        mock_disk.assert_called_once_with(fake_disk_path, allow_write=True)

    @testutils.ConfPatcher("set_unique_boot_disk_id", True)
    @mock.patch(MODPATH + ".BCDConfigPlugin._set_unique_disk_id")
    @mock.patch("cloudbaseinit.utils.windows.bootconfig."
                "enable_auto_recovery")
    @mock.patch("cloudbaseinit.utils.windows.bootconfig."
                "set_current_bcd_device_to_boot_partition")
    @mock.patch("cloudbaseinit.utils.windows.bootconfig."
                "get_boot_system_devices")
    def test_execute_bcd_config(self, mock_get_boot,
                                mock_set_current_bcd,
                                mock_enable_auto_recovery,
                                mock_set_unique_disk_id):
        mock_service = mock.Mock()
        mock_shared_data = mock.Mock()
        expected_res = (base.PLUGIN_EXECUTION_DONE, False)
        expected_logs = ["Configuring boot device"]
        mock_get_boot.return_value = "1"
        with self.snatcher:
            res_execute = self.bcd_config.execute(mock_service,
                                                  mock_shared_data)
        self.assertEqual(self.snatcher.output, expected_logs)
        self.assertEqual(res_execute, expected_res)
        mock_get_boot.assert_called_once_with()
        mock_set_current_bcd.assert_called_once_with()
        mock_set_unique_disk_id.assert_called_once_with(
            u"\\\\.\\PHYSICALDRIVE0")

    def test_get_os_requirements(self):
        expected_res = ('win32', (6, 0))
        res_plugin = self.boot_policy_plugin.get_os_requirements()
        res_config = self.bcd_config.get_os_requirements()
        for res in (res_plugin, res_config):
            self.assertEqual(res, expected_res)
