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

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


MODPATH = "cloudbaseinit.utils.windows.bootconfig"


class BootConfigTest(unittest.TestCase):

    def setUp(self):
        self._wmi_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules', {
                "wmi": self._wmi_mock})
        self.snatcher = testutils.LogSnatcher(MODPATH)
        self._module_patcher.start()
        self.bootconfig = importlib.import_module(MODPATH)

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_run_bcdedit(self, mock_get_os_utils, ret_val=0):
        mock_osutils = mock.Mock()
        mock_get_os_utils.return_value = mock_osutils
        mock_args = [mock.sentinel.args]
        expected_call = ["bcdedit.exe"] + mock_args
        mock_osutils.execute_system32_process.return_value = (
            mock.sentinel.out_val, mock.sentinel.err, ret_val)
        if ret_val:
            self.assertRaises(exception.CloudbaseInitException,
                              self.bootconfig._run_bcdedit, mock_args)
        else:
            self.bootconfig._run_bcdedit(mock_args)
        mock_osutils.execute_system32_process.assert_called_once_with(
            expected_call)

    def test_run_bcdedit(self):
        self._test_run_bcdedit()

    def test_run_bcdedit_fail(self):
        self._test_run_bcdedit(ret_val=1)

    @mock.patch(MODPATH + "._run_bcdedit")
    def test_set_boot_status_policy(self, mock_run_bcdedit):
        fake_policy = mock.sentinel.policy
        expected_logs = ["Setting boot status policy: %s" % fake_policy]
        with self.snatcher:
            self.bootconfig.set_boot_status_policy(fake_policy)
        mock_run_bcdedit.assert_called_once_with(
            ["/set", "{current}", "bootstatuspolicy", fake_policy])
        self.assertEqual(expected_logs, self.snatcher.output)

    def test_get_boot_system_devices(self):
        mock_vol = mock.Mock()
        mock_win32volume = mock.MagicMock()
        mock_id = mock.sentinel.id
        mock_vol.DeviceID = mock_id
        conn = self._wmi_mock.WMI
        conn.return_value = mock_win32volume
        mock_win32volume.Win32_Volume.return_value = [mock_vol]
        expected_call_args = {"BootVolume": True, "SystemVolume": True}

        res = self.bootconfig.get_boot_system_devices()
        mock_win32volume.Win32_Volume.assert_called_once_with(
            **expected_call_args)
        self.assertEqual(res, [mock_id])

    def _test_get_current_bcd_store(self, mock_success=True, mock_store=None):
        conn = self._wmi_mock.WMI
        store = self._wmi_mock._wmi_object
        mock_store = mock.Mock()
        mock_bcdstore = mock.MagicMock()
        conn.return_value = mock_bcdstore
        store.return_value = mock_store
        mock_bcdstore.BcdStore.OpenStore.return_value = (mock_success,
                                                         mock_store)
        if not mock_success:
            self.assertRaises(
                exception.CloudbaseInitException,
                self.bootconfig._get_current_bcd_store)
        else:
            mock_store.OpenObject.return_value = [None, mock_success]
            res_store = self.bootconfig._get_current_bcd_store()
            self.assertEqual(res_store, mock_store)

    def test_get_current_bcd_store(self):
        self._test_get_current_bcd_store()

    def test_get_current_bcd_store_fail(self):
        self._test_get_current_bcd_store(mock_success=False)

    @mock.patch(MODPATH + "._get_current_bcd_store")
    def _test_set_current_bcd_device_to_boot_partition(
            self, mock_get_current_bcd_store, side_effects=True,
            success_set_os=True, success_set_app=True):
        mock_store = mock.Mock()
        mock_get_current_bcd_store.return_value = mock_store
        mock_store.SetDeviceElement.side_effect = ([success_set_os],
                                                   [success_set_app])

        if not success_set_os:
            self.assertRaises(
                exception.CloudbaseInitException,
                self.bootconfig.set_current_bcd_device_to_boot_partition)
            self.assertEqual(mock_store.SetDeviceElement.call_count, 1)

        elif success_set_os and not success_set_app:
            self.assertRaises(
                exception.CloudbaseInitException,
                self.bootconfig.set_current_bcd_device_to_boot_partition)
            self.assertEqual(mock_store.SetDeviceElement.call_count, 2)

        elif success_set_os and success_set_app:
            self.bootconfig.set_current_bcd_device_to_boot_partition()
            self.assertEqual(mock_store.SetDeviceElement.call_count, 2)
        mock_get_current_bcd_store.assert_called_once_with()

    def test_set_current_bcd_device_to_boot_partition_success(self):
        self._test_set_current_bcd_device_to_boot_partition()

    def test_set_current_bcd_device_to_boot_partition_fail_os(self):
        self._test_set_current_bcd_device_to_boot_partition(
            success_set_os=False)

    def test_set_current_bcd_device_to_boot_partition_fail_app(self):
        self._test_set_current_bcd_device_to_boot_partition(
            success_set_app=False)

    @mock.patch(MODPATH + "._get_current_bcd_store")
    def _test_enable_auto_recovery(self, mock_get_current_bcd_store,
                                   mock_success=True, mock_enable=True):
        mock_store = mock.Mock()
        mock_get_current_bcd_store.return_value = mock_store
        mock_store.SetBooleanElement.side_effect = ((mock_success,),)
        expected_call = (
            self.bootconfig.BCDLIBRARY_BOOLEAN_AUTO_RECOVERY_ENABLED,
            mock_enable)
        if not mock_success:
            self.assertRaises(exception.CloudbaseInitException,
                              self.bootconfig.enable_auto_recovery,
                              mock_enable)
        else:
            self.bootconfig.enable_auto_recovery(enable=mock_enable)
        mock_store.SetBooleanElement.assert_called_once_with(
            *expected_call)

    def test_enable_auto_recovery(self):
        self._test_enable_auto_recovery()

    def test_enable_auto_recovery_failed(self):
        self._test_enable_auto_recovery(mock_success=False)
