# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
import mock
import os
import sys
import unittest

from oslo.config import cfg

CONF = cfg.CONF
_win32com_mock = mock.MagicMock()
_ctypes_mock = mock.MagicMock()
_ctypes_util_mock = mock.MagicMock()
_win32com_client_mock = mock.MagicMock()
_pywintypes_mock = mock.MagicMock()
_mock_dict = {'win32com': _win32com_mock,
              'ctypes': _ctypes_mock,
              'ctypes.util': _ctypes_util_mock,
              'win32com.client': _win32com_client_mock,
              'pywintypes': _pywintypes_mock}


class ConfigDriveServiceTest(unittest.TestCase):
    @mock.patch.dict(sys.modules, _mock_dict)
    def setUp(self):
        configdrive = importlib.import_module('cloudbaseinit.metadata.services'
                                              '.configdrive')
        self._config_drive = configdrive.ConfigDriveService()

    def tearDown(self):
        reload(sys)

    @mock.patch('os.path.normpath')
    @mock.patch('os.path.join')
    def test_get_data(self, mock_join, mock_normpath):
        fake_path = os.path.join('fake', 'path')
        with mock.patch('__builtin__.open',
                        mock.mock_open(read_data='fake data'), create=True):
            response = self._config_drive._get_data(fake_path)
            self.assertEqual(response, 'fake data')
            mock_join.assert_called_with(
                self._config_drive._metadata_path, fake_path)

    @mock.patch('shutil.rmtree')
    def test_cleanup(self, mock_rmtree):
        fake_path = os.path.join('fake', 'path')
        self._config_drive._metadata_path = fake_path
        self._config_drive.cleanup()
        self.assertEqual(self._config_drive._metadata_path, None)
