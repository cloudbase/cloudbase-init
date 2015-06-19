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

import unittest

import mock

from cloudbaseinit import version


class TestVersion(unittest.TestCase):

    @mock.patch('pbr.version.VersionInfo')
    def test_get_version(self, mock_version_info):
        package_version = version.get_version()

        mock_version_info.assert_called_once_with('cloudbase-init')
        release_string = mock_version_info.return_value.release_string
        self.assertEqual(release_string.return_value, package_version)
