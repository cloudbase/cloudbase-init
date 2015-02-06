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

import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.osutils import factory


class OSUtilsFactory(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def _test_get_os_utils(self, mock_load_class, fake_name):
        os.name = fake_name
        factory.get_os_utils()
        if fake_name == 'nt':
            mock_load_class.assert_called_with(
                'cloudbaseinit.osutils.windows.WindowsUtils')
        elif fake_name == 'posix':
            mock_load_class.assert_called_with(
                'cloudbaseinit.osutils.posix.PosixUtils')

    def test_get_os_utils_windows(self):
        self._test_get_os_utils(fake_name='nt')

    def test_get_os_utils_posix(self):
        self._test_get_os_utils(fake_name='posix')
