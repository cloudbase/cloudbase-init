# Copyright 2013 Cloudbase Solutions Srl
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

from cloudbaseinit.metadata.services import baseconfigdrive
from cloudbaseinit.tests import testutils

MODULE_PATH = "cloudbaseinit.metadata.services.configdrive"


class TestConfigDriveService(unittest.TestCase):

    def setUp(self):
        self._win32com_mock = mock.MagicMock()
        self._ctypes_mock = mock.MagicMock()
        self._ctypes_util_mock = mock.MagicMock()
        self._win32com_client_mock = mock.MagicMock()
        self._pywintypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'win32com': self._win32com_mock,
             'ctypes': self._ctypes_mock,
             'ctypes.util': self._ctypes_util_mock,
             'win32com.client': self._win32com_client_mock,
             'pywintypes': self._pywintypes_mock})
        self._module_patcher.start()
        self.addCleanup(self._module_patcher.stop)

        self.configdrive_module = importlib.import_module(MODULE_PATH)
        self._drive_label = 'config-2'
        self._metadata_file = 'openstack\\latest\\meta_data.json'
        self._config_drive = self.configdrive_module.ConfigDriveService()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.factory.'
                'get_config_drive_manager')
    def test_load(self, mock_get_config_drive_manager):
        mock_manager = mock.MagicMock()
        mock_manager.get_config_drive_files.return_value = True
        fake_path = "fake\\fake_id"
        mock_manager.target_path = fake_path
        mock_get_config_drive_manager.return_value = mock_manager

        response = self._config_drive.load()

        mock_get_config_drive_manager.assert_called_once_with()
        mock_manager.get_config_drive_files.assert_called_once_with(
            drive_label=self._drive_label,
            metadata_file=self._metadata_file,
            searched_types=baseconfigdrive.CD_TYPES,
            searched_locations=baseconfigdrive.CD_LOCATIONS)
        self.assertTrue(response)
        self.assertEqual(fake_path, self._config_drive._metadata_path)
