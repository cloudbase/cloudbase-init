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

import mock
import os
import unittest

from cloudbaseinit.plugins import base
from cloudbaseinit.plugins.windows import localscripts
from oslo.config import cfg

CONF = cfg.CONF


class LocalScriptsPluginTests(unittest.TestCase):

    def setUp(self):
        self._localscripts = localscripts.LocalScriptsPlugin()

    @mock.patch('os.listdir')
    @mock.patch('os.path.isfile')
    def test_get_files_in_dir(self, mock_isfile, mock_listdir):
        fake_path = os.path.join('fake', 'path')
        fake_file_list = ['second', 'first', 'third', 'last']
        mock_isfile.return_value = True
        mock_listdir.return_value = fake_file_list
        response = self._localscripts._get_files_in_dir(fake_path)
        mock_listdir.assert_called_once_with(fake_path)
        self.assertEqual(
            sorted(os.path.join(fake_path, f) for f in fake_file_list),
            response)

    @mock.patch('cloudbaseinit.plugins.windows.localscripts'
                '.LocalScriptsPlugin._get_files_in_dir')
    @mock.patch('cloudbaseinit.plugins.windows.fileexecutils.exec_file')
    def test_execute(self, mock_exec_file, mock_get_files_in_dir):
        mock_service = mock.MagicMock()
        fake_path = os.path.join('fake', 'path')
        CONF.set_override('local_scripts_path', True)

        mock_get_files_in_dir.return_value = [fake_path]

        response = self._localscripts.execute(mock_service, shared_data=None)

        mock_get_files_in_dir.assert_called_once_with(CONF.local_scripts_path)
        mock_exec_file.assert_called_once_with(fake_path)
        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)
