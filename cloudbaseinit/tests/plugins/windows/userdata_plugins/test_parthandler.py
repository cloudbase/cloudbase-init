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
import unittest

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.plugins.windows import userdata_plugins
#the name of the module includes "-", importlib.import_module is needed:
parthandler = importlib.import_module("cloudbaseinit.plugins.windows"
                                      ".userdata-plugins.parthandler")

CONF = cfg.CONF


class PartHandlerScriptHandlerTests(unittest.TestCase):

    def setUp(self):
        parent_set = userdata_plugins.PluginSet('fake_path')
        self._parthandler = parthandler.PartHandlerScriptHandler(parent_set)

    @mock.patch('imp.load_source')
    @mock.patch('imp.load_compiled')
    @mock.patch('cloudbaseinit.plugins.windows.userdata-plugins.parthandler'
                '.__import__', create=True)
    def _test_load_from_file(self, mock__import__, mock_load_compiled,
                             mock_load_source, filepath):
        mock_module = mock.MagicMock()
        mock__import__.return_value = mock_module
        mod_name, file_ext = os.path.splitext(os.path.split(filepath)[-1])
        response = parthandler.load_from_file(filepath, 'fake_function')
        print response
        if file_ext.lower() == '.py':
            mock_load_source.assert_called_with('path', filepath)
        elif file_ext.lower() == '.pyc':
            mock_load_compiled.assert_called_with('path', filepath)
        mock__import__.assert_called_once_with('path')
        self.assertEqual(response, mock_module.fake_function)

    def test_load_from_file_py(self):
        fake_file_path = os.path.join(os.path.join('fake', 'file'), 'path')
        self._test_load_from_file(filepath=fake_file_path + '.py')

    def test_load_from_file_pyc(self):
        fake_file_path = os.path.join(os.path.join('fake', 'file'), 'path')
        self._test_load_from_file(filepath=fake_file_path + '.pyc')

    @mock.patch('cloudbaseinit.plugins.windows.userdata-plugins.parthandler.'
                'load_from_file')
    def test_process(self, mock_load_from_file):
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = 'fake_name'
        handler_path = self._parthandler.parent_set.path + "/part-handler/"
        handler_path += 'fake_name'
        expected = [mock.call(),
                    mock.call(handler_path, "list_types"),
                    mock.call(handler_path, "handle_part")]
        mock_load_from_file().return_value = ['fake part']
        with mock.patch("cloudbaseinit.plugins.windows.userdata-plugins."
                        "parthandler.open", mock.mock_open(), create=True):
            self._parthandler.process(mock_part)

            print mock_load_from_file.mock_calls
            print self._parthandler.parent_set.custom_handlers

        mock_part.get_filename.assert_called_once_with()
        mock_part.get_payload.assert_called_once_with()
        self.assertEqual(mock_load_from_file.call_args_list, expected)
        self.assertEqual(self._parthandler.parent_set.has_custom_handlers,
                         True)
        self.assertEqual(self._parthandler.parent_set.custom_handlers,
                         {'fake part': mock_load_from_file()})
