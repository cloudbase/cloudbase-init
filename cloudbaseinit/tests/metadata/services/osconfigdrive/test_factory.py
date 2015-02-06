# Copyright 2014 Cloudbase Solutions Srl
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

import sys
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.metadata.services.osconfigdrive import factory


class ClassloaderTest(unittest.TestCase):

    def setUp(self):
        self.original_platform = sys.platform

    def tearDown(self):
        sys.platform = self.original_platform

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def _test_get_config_drive_manager(self, mock_load_class, platform):
        sys.platform = platform

        if platform is not "win32":
            self.assertRaises(NotImplementedError,
                              factory.get_config_drive_manager)

        else:
            response = factory.get_config_drive_manager()

            mock_load_class.assert_called_once_with(
                'cloudbaseinit.metadata.services.osconfigdrive.'
                'windows.WindowsConfigDriveManager')

            self.assertIsNotNone(response)

    def test_get_config_drive_manager(self):
        self._test_get_config_drive_manager(platform="win32")

    def test_get_config_drive_manager_exception(self):
        self._test_get_config_drive_manager(platform="other")
