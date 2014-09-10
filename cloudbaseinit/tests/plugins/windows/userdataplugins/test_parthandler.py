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

import mock
import os
import unittest

from oslo.config import cfg

from cloudbaseinit.plugins.windows.userdataplugins import parthandler

CONF = cfg.CONF


class PartHandlerPluginTests(unittest.TestCase):

    def setUp(self):
        self._parthandler = parthandler.PartHandlerPlugin()

    @mock.patch('tempfile.gettempdir')
    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_module')
    def test_process(self, mock_load_module, mock_gettempdir):
        mock_part = mock.MagicMock()
        mock_part_handler = mock.MagicMock()
        mock_part.get_filename.return_value = 'fake_name'
        mock_gettempdir.return_value = 'fake_directory'
        mock_load_module.return_value = mock_part_handler
        mock_part_handler.list_types.return_value = ['fake part']

        with mock.patch('cloudbaseinit.plugins.windows.userdataplugins.'
                        'parthandler.open',
                        mock.mock_open(read_data='fake data'), create=True):
            response = self._parthandler.process(mock_part)

        mock_part.get_filename.assert_called_once_with()
        mock_load_module.assert_called_once_with(os.path.join(
            'fake_directory', 'fake_name'))
        mock_part_handler.list_types.assert_called_once_with()
        self.assertEqual({'fake part': mock_part_handler.handle_part},
                         response)
