# Copyright 2020 Cloudbase Solutions Srl
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
import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.tests import testutils

MODULE_PATH = "cloudbaseinit.metadata.services.nocloudservice"


class TestNoCloudConfigDriveService(unittest.TestCase):

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
        self._config_drive = (
            self.configdrive_module.NoCloudConfigDriveService())
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @mock.patch('os.path.normpath')
    @mock.patch('os.path.join')
    def test_get_data(self, mock_join, mock_normpath):
        fake_path = os.path.join('fake', 'path')
        with mock.patch('six.moves.builtins.open',
                        mock.mock_open(read_data='fake data'), create=True):
            response = self._config_drive._get_data(fake_path)
            self.assertEqual('fake data', response)
            mock_join.assert_called_with(
                self._config_drive._metadata_path, fake_path)
            mock_normpath.assert_called_once_with(mock_join.return_value)

    @mock.patch('shutil.rmtree')
    def test_cleanup(self, mock_rmtree):
        fake_path = os.path.join('fake', 'path')
        self._config_drive._metadata_path = fake_path
        mock_mgr = mock.Mock()
        self._config_drive._mgr = mock_mgr
        mock_mgr.target_path = fake_path
        self._config_drive.cleanup()
        mock_rmtree.assert_called_once_with(fake_path,
                                            ignore_errors=True)
        self.assertEqual(None, self._config_drive._metadata_path)

    @mock.patch(MODULE_PATH + '.NoCloudConfigDriveService._get_meta_data')
    def test_get_public_keys(self, mock_get_metadata):
        fake_key = 'fake key'
        expected_result = [fake_key]
        mock_get_metadata.return_value = {
            'public-keys': {
                '0': {
                    'openssh-key': fake_key
                }
            }
        }
        result = self._config_drive.get_public_keys()
        self.assertEqual(result, expected_result)
