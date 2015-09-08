# Copyright 2015 Cloudbase Solutions Srl
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


import ctypes as _    # noqa
import importlib
import unittest

import mock


class TestStorageManager(unittest.TestCase):

    def setUp(self):
        self.mock_os = mock.MagicMock()
        patcher = mock.patch.dict(
            "sys.modules",
            {
                "os": self.mock_os
            }
        )
        patcher.start()

        self.factory = importlib.import_module(
            "cloudbaseinit.utils.windows.storage.factory")
        self.addCleanup(patcher.stop)

    @mock.patch("cloudbaseinit.utils.classloader.ClassLoader")
    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def _test_get_storage_manager(self, mock_get_os_utils, mock_class_loader,
                                  nano=False, fail=False):
        if fail:
            self.mock_os.name = "linux"
            with self.assertRaises(NotImplementedError):
                self.factory.get_storage_manager()
            return

        self.mock_os.name = "nt"
        mock_get_os_utils.return_value.check_os_version.return_value = nano
        mock_load_class = mock_class_loader.return_value.load_class
        response = self.factory.get_storage_manager()
        if nano:
            class_path = ("cloudbaseinit.utils.windows.storage."
                          "wsm_storage_manager.WSMStorageManager")
        else:
            class_path = ("cloudbaseinit.utils.windows.storage."
                          "vds_storage_manager.VDSStorageManager")
        mock_load_class.assert_called_once_with(class_path)
        self.assertEqual(mock_load_class.return_value.return_value,
                         response)

    def test_get_storage_manager_fail(self):
        self._test_get_storage_manager(fail=True)

    def test_get_storage_manager_nano(self):
        self._test_get_storage_manager(nano=True)

    def test_get_storage_manager(self):
        self._test_get_storage_manager()
