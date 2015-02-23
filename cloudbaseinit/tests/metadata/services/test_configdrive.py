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
import os
import unittest
import uuid

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo.config import cfg

CONF = cfg.CONF


class ConfigDriveServiceTest(unittest.TestCase):

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

        configdrive = importlib.import_module('cloudbaseinit.metadata.services'
                                              '.configdrive')
        self._config_drive = configdrive.ConfigDriveService()

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('tempfile.gettempdir')
    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.factory.'
                'get_config_drive_manager')
    def test_load(self, mock_get_config_drive_manager,
                  mock_gettempdir):
        mock_manager = mock.MagicMock()
        mock_manager.get_config_drive_files.return_value = True
        mock_get_config_drive_manager.return_value = mock_manager
        mock_gettempdir.return_value = 'fake'
        uuid.uuid4 = mock.MagicMock(return_value='fake_id')
        fake_path = os.path.join('fake', str('fake_id'))

        response = self._config_drive.load()

        mock_gettempdir.assert_called_once_with()
        mock_get_config_drive_manager.assert_called_once_with()
        mock_manager.get_config_drive_files.assert_called_once_with(
            fake_path,
            check_raw_hhd=CONF.config_drive_raw_hhd,
            check_cdrom=CONF.config_drive_cdrom,
            check_vfat=CONF.config_drive_vfat)
        self.assertTrue(response)
        self.assertEqual(fake_path, self._config_drive._metadata_path)

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

    @mock.patch('shutil.rmtree')
    def test_cleanup(self, mock_rmtree):
        fake_path = os.path.join('fake', 'path')
        self._config_drive._metadata_path = fake_path
        self._config_drive.cleanup()
        self.assertEqual(None, self._config_drive._metadata_path)
