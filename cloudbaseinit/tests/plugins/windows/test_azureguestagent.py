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

import datetime
import importlib
import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.plugins.windows.azureguestagent"


class AzureGuestAgentPluginTest(unittest.TestCase):

    def setUp(self):
        self.mock_wmi = mock.MagicMock()
        self._moves_mock = mock.MagicMock()
        patcher = mock.patch.dict(
            "sys.modules",
            {
                "wmi": self.mock_wmi,
                "six.moves": self._moves_mock
            }
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self._winreg_mock = self._moves_mock.winreg
        self._azureguestagent = importlib.import_module(MODPATH)
        self._azureagentplugin = self._azureguestagent.AzureGuestAgentPlugin()
        self.snatcher = testutils.LogSnatcher(MODPATH)

    def test_check_delete_service(self):
        mock_osutils = mock.Mock()
        mock_service_name = mock.sentinel.name
        self._azureagentplugin._check_delete_service(mock_osutils,
                                                     mock_service_name)
        mock_osutils.check_service_exists.assert_called_once_with(
            mock_service_name)
        mock_osutils.get_service_status.assert_called_once_with(
            mock_service_name)
        mock_osutils.stop_service.assert_called_once_with(mock_service_name,
                                                          wait=True)
        mock_osutils.delete_service.assert_called_once_with(mock_service_name)

    @mock.patch(MODPATH + ".AzureGuestAgentPlugin._check_delete_service")
    def test_remove_agent_services(self, mock_check_delete_service):
        mock_osutils = mock.Mock()
        expected_logs = ["Stopping and removing any existing Azure guest "
                         "agent services"]
        with self.snatcher:
            self._azureagentplugin._remove_agent_services(mock_osutils)
        self.assertEqual(self.snatcher.output, expected_logs)
        self.assertEqual(mock_check_delete_service.call_count, 3)

    @mock.patch("shutil.rmtree")
    @mock.patch("os.path.exists")
    @mock.patch("os.getenv")
    def test_remove_azure_dirs(self, mock_os_getenv,
                               mock_exists, mock_rmtree):
        mock_rmtree.side_effect = (None, Exception)
        mock_exists.return_value = True
        mock_os_getenv.return_value = "fake_path"
        with self.snatcher:
            self._azureagentplugin._remove_azure_dirs()
        mock_os_getenv.assert_called_with("SystemDrive")
        self.assertEqual(mock_os_getenv.call_count, 2)
        self.assertEqual(mock_exists.call_count, 2)
        self.assertEqual(mock_rmtree.call_count, 2)

    def test_set_registry_vm_type(self):
        vm_type = mock.sentinel.vm
        key_name = "SOFTWARE\\Microsoft\\Windows Azure"

        self._azureagentplugin._set_registry_vm_type(vm_type)
        key = self._winreg_mock.CreateKey.return_value.__enter__.return_value
        self._winreg_mock.CreateKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE, key_name)
        self._winreg_mock.SetValueEx.assert_called_once_with(
            key, "VMType", 0, self._winreg_mock.REG_SZ, vm_type)

    def test_set_registry_ga_params(self):
        fake_version = (1, 2, 3, 4)
        fake_install_timestamp = datetime.datetime.now()
        key_name = "SOFTWARE\\Microsoft\\GuestAgent"

        self._azureagentplugin._set_registry_ga_params(fake_version,
                                                       fake_install_timestamp)

        self._winreg_mock.CreateKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE, key_name)
        self.assertEqual(self._winreg_mock.SetValueEx.call_count, 2)

    @mock.patch(MODPATH + ".AzureGuestAgentPlugin._set_registry_ga_params")
    @mock.patch(MODPATH + ".AzureGuestAgentPlugin._set_registry_vm_type")
    def test_configure_rd_agent(self, mock_set_registry_vm_type,
                                mock_set_registry_ga_params):
        mock_osutils = mock.Mock()
        fake_ga_path = "C:\\"
        expected_rd_path = os.path.join(fake_ga_path,
                                        self._azureguestagent.RDAGENT_FILENAME)
        expected_path = os.path.join(fake_ga_path, "TransparentInstaller.dll")
        self._azureagentplugin._configure_rd_agent(mock_osutils, fake_ga_path)
        mock_osutils.create_service.assert_called_once_with(
            self._azureguestagent.SERVICE_NAME_RDAGENT,
            self._azureguestagent.SERVICE_NAME_RDAGENT,
            expected_rd_path,
            mock_osutils.SERVICE_START_MODE_MANUAL)
        mock_osutils.get_file_version.assert_called_once_with(expected_path)
        mock_set_registry_vm_type.assert_called_once_with()

    @mock.patch(MODPATH + ".AzureGuestAgentPlugin._run_logman")
    def test_stop_event_trace(self, mock_run_logman):
        mock_osutils = mock.Mock()
        fake_name = mock.sentinel.event_name
        res = self._azureagentplugin._stop_event_trace(mock_osutils, fake_name)
        mock_run_logman.assert_called_once_with(mock_osutils, "stop",
                                                fake_name, False)
        self.assertIsNotNone(res)

    @mock.patch(MODPATH + ".AzureGuestAgentPlugin._run_logman")
    def test_delete_event_trace(self, mock_run_logman):
        mock_osutils = mock.Mock()
        fake_name = mock.sentinel.event_name
        res = self._azureagentplugin._delete_event_trace(mock_osutils,
                                                         fake_name)
        mock_run_logman.assert_called_once_with(mock_osutils, "delete",
                                                fake_name)
        self.assertIsNotNone(res)

    def test_run_logman(self):
        mock_osutils = mock.Mock()
        fake_action = mock.sentinel.action
        fake_name = mock.sentinel.cmd_name
        expected_args = ["logman.exe", "-ets", fake_action, fake_name]
        mock_osutils.execute_system32_process.return_value = (0, 0, -1)
        self._azureagentplugin._run_logman(mock_osutils, fake_action,
                                           fake_name, True)
        mock_osutils.execute_system32_process.assert_called_once_with(
            expected_args)

    @mock.patch(MODPATH + ".AzureGuestAgentPlugin._stop_event_trace")
    def test_stop_ga_event_traces(self, mock_stop_event_trace):
        mock_osutils = mock.Mock()
        expected_logs = ["Stopping Azure guest agent event traces"]
        with self.snatcher:
            self._azureagentplugin._stop_ga_event_traces(mock_osutils)
        self.assertEqual(mock_stop_event_trace.call_count, 4)
        self.assertEqual(self.snatcher.output, expected_logs)

    @mock.patch(MODPATH + ".AzureGuestAgentPlugin._delete_event_trace")
    def test_delete_ga_event_traces(self, mock_delete_event_trace):
        mock_osutils = mock.Mock()
        expected_logs = ["Deleting Azure guest agent event traces"]
        with self.snatcher:
            self._azureagentplugin._delete_ga_event_traces(mock_osutils)
        self.assertEqual(mock_delete_event_trace.call_count, 2)
        self.assertEqual(self.snatcher.output, expected_logs)

    @mock.patch("os.path.exists")
    def _test_get_guest_agent_source_path(self, mock_exists,
                                          drives=None, exists=False):
        mock_osutils = mock.Mock()
        mock_exists.return_value = exists
        mock_osutils.get_logical_drives.return_value = drives
        if not exists:
            self.assertRaises(
                exception.CloudbaseInitException,
                self._azureagentplugin._get_guest_agent_source_path,
                mock_osutils)
            return
        res = self._azureagentplugin._get_guest_agent_source_path(mock_osutils)
        self.assertIsNotNone(res)

    def test_get_guest_agent_source_path_no_agent(self):
        self._test_get_guest_agent_source_path(drives=[])

    def test_get_guest_agent_source_path(self):
        mock_drive = "C:"
        self._test_get_guest_agent_source_path(drives=[mock_drive],
                                               exists=True)

    def _test_execute(self,
                      provisioning_data=None, expected_logs=None):
        mock_service = mock.Mock()
        mock_sharedata = mock.Mock()
        expected_res = (base.PLUGIN_EXECUTION_DONE, False)
        (mock_service.get_vm_agent_package_provisioning_data.
            return_value) = provisioning_data
        if not provisioning_data or not provisioning_data.get("provision"):
            with self.snatcher:
                res = self._azureagentplugin.execute(mock_service,
                                                     mock_sharedata)
            (mock_service.get_vm_agent_package_provisioning_data.
                assert_called_once_with())
            self.assertEqual(res, expected_res)
            self.assertEqual(self.snatcher.output, expected_logs)
            return

    def test_execute_no_data(self):
        expected_logs = ["Azure guest agent provisioning data not present"]
        self._test_execute(expected_logs=expected_logs)

    def test_execute_no_provision(self):
        mock_data = {"provision": None}
        expected_logs = ["Skipping Azure guest agent provisioning "
                         "as by metadata request"]
        self._test_execute(provisioning_data=mock_data,
                           expected_logs=expected_logs)

    def test_get_os_requirements(self):
        expected_res = ('win32', (6, 1))
        res = self._azureagentplugin.get_os_requirements()
        self.assertEqual(res, expected_res)
