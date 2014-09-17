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
import re
import unittest

from oslo.config import cfg

from cloudbaseinit import exception
from cloudbaseinit.plugins import base
from cloudbaseinit.plugins.windows import networkconfig
from cloudbaseinit.tests.metadata import fake_json_response

CONF = cfg.CONF


class NetworkConfigPluginPluginTests(unittest.TestCase):

    def setUp(self):
        self._network_plugin = networkconfig.NetworkConfigPlugin()
        self.fake_data = fake_json_response.get_fake_metadata_json(
            '2013-04-04')

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_execute(self, mock_get_os_utils, search_result, no_adapters):
        CONF.set_override('network_adapter', 'fake adapter')
        mock_service = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        re.search = mock.MagicMock(return_value=search_result)
        fake_shared_data = 'fake shared data'
        network_config = self.fake_data['network_config']
        mock_service.get_network_config.return_value = network_config
        mock_service.get_content.return_value = search_result
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.set_static_network_config.return_value = False
        if search_result is None:
            self.assertRaises(exception.CloudbaseInitException,
                              self._network_plugin.execute,
                              mock_service, fake_shared_data)
        elif no_adapters:
            CONF.set_override('network_adapter', None)
            mock_osutils.get_network_adapters.return_value = []
            self.assertRaises(exception.CloudbaseInitException,
                              self._network_plugin.execute,
                              mock_service, fake_shared_data)

        else:
            response = self._network_plugin.execute(mock_service,
                                                    fake_shared_data)

            mock_service.get_network_config.assert_called_once_with()
            mock_service.get_content.assert_called_once_with(
                network_config['content_path'])
            mock_osutils.set_static_network_config.assert_called_once_with(
                'fake adapter', search_result.group('address'),
                search_result.group('netmask'),
                search_result.group('broadcast'),
                search_result.group('gateway'),
                search_result.group('dnsnameservers').strip().split(' '))
            self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute(self):
        m = mock.MagicMock()
        self._test_execute(search_result=m, no_adapters=False)

    def test_execute_no_debian(self):
        self._test_execute(search_result=None, no_adapters=False)

    def test_execute_no_adapters(self):
        m = mock.MagicMock()
        self._test_execute(search_result=m, no_adapters=True)
