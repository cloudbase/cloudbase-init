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

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


class TestConfigDriveService(unittest.TestCase):

    def setUp(self):
        module_path = "cloudbaseinit.metadata.services.configdrive"
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

        self.configdrive_module = importlib.import_module(module_path)
        self._config_drive = self.configdrive_module.ConfigDriveService()
        self.snatcher = testutils.LogSnatcher(module_path)

    def _test_preprocess_options(self, fail=False):
        if fail:
            with testutils.ConfPatcher("types", ["vfat", "ntfs"],
                                       group="config_drive"):
                with self.assertRaises(exception.CloudbaseInitException):
                    self._config_drive._preprocess_options()
            with testutils.ConfPatcher("locations", ["device"],
                                       group="config_drive"):
                with self.assertRaises(exception.CloudbaseInitException):
                    self._config_drive._preprocess_options()
            return

        options = {
            "raw_hdd": False,
            "cdrom": False,
            "vfat": True,
            # Deprecated options above.
            "types": ["vfat", "iso"],
            "locations": ["partition"]
        }
        contexts = [testutils.ConfPatcher(key, value, group="config_drive")
                    for key, value in options.items()]
        with contexts[0], contexts[1], contexts[2], \
                contexts[3], contexts[4]:
            self._config_drive._preprocess_options()
            self.assertEqual({"vfat", "iso"},
                             self._config_drive._searched_types)
            self.assertEqual({"hdd", "partition"},
                             self._config_drive._searched_locations)

    def test_preprocess_options_fail(self):
        self._test_preprocess_options(fail=True)

    def test_preprocess_options(self):
        self._test_preprocess_options()

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.factory.'
                'get_config_drive_manager')
    def test_load(self, mock_get_config_drive_manager):
        mock_manager = mock.MagicMock()
        mock_manager.get_config_drive_files.return_value = True
        fake_path = "fake\\fake_id"
        mock_manager.target_path = fake_path
        mock_get_config_drive_manager.return_value = mock_manager
        expected_log = [
            "Metadata copied to folder: %r" % fake_path]

        with self.snatcher:
            response = self._config_drive.load()

        mock_get_config_drive_manager.assert_called_once_with()
        mock_manager.get_config_drive_files.assert_called_once_with(
            searched_types=self.configdrive_module.CD_TYPES,
            searched_locations=self.configdrive_module.CD_LOCATIONS)
        self.assertEqual(expected_log, self.snatcher.output)
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
            mock_normpath.assert_called_once_with(mock_join.return_value)

    @mock.patch('shutil.rmtree')
    def test_cleanup(self, mock_rmtree):
        fake_path = os.path.join('fake', 'path')
        self._config_drive._metadata_path = fake_path
        mock_mgr = mock.Mock()
        self._config_drive._mgr = mock_mgr
        mock_mgr.target_path = fake_path
        with self.snatcher:
            self._config_drive.cleanup()
        self.assertEqual(["Deleting metadata folder: %r" % fake_path],
                         self.snatcher.output)
        mock_rmtree.assert_called_once_with(fake_path,
                                            ignore_errors=True)
        self.assertEqual(None, self._config_drive._metadata_path)
