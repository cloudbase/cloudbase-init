# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis Inc.
# All Rights Reserved.
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

import mock
import unittest

from cloudbaseinit.plugins.windows import userdata_plugins


class MultipartUserDataPluginTest(unittest.TestCase):

    def setUp(self):
        fake_path = 'fake path'
        self._userdata = userdata_plugins.PluginSet(fake_path)

    @mock.patch('glob.glob')
    @mock.patch('cloudbaseinit.plugins.windows.userdata_plugins.'
                'load_from_file')
    def test_load(self, mock_load_from_file, mock_glob):
        fake_files = ['fake_file.py']
        mock_plugin = mock.MagicMock()
        mock_glob.return_value = fake_files
        mock_load_from_file.return_value = mock_plugin

        self._userdata.load()
        mock_glob.assert_called_once_with(self._userdata.path + '/*.py')
        mock_load_from_file.assert_called_once_with('fake_file.py',
                                                    self._userdata)
        self.assertEqual(self._userdata.set[mock_plugin.type], mock_plugin)
