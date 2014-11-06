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


import re
import unittest

import mock
from oslo.config import cfg

from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base as service_base
from cloudbaseinit.plugins import base as plugin_base
from cloudbaseinit.plugins.windows import networkconfig
from cloudbaseinit.tests.metadata import fake_json_response


CONF = cfg.CONF


class TestNetworkConfigPlugin(unittest.TestCase):

    def setUp(self):
        self._network_plugin = networkconfig.NetworkConfigPlugin()
        self.fake_data = fake_json_response.get_fake_metadata_json(
            '2013-04-04')

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_execute(self, mock_get_os_utils,
                      search_result=mock.MagicMock(),
                      no_adapter_name=False, no_adapters=False,
                      using_content=0, details_list=None,
                      missing_content_path=False):
        fake_adapter = ("fake_name_0", "fake_mac_0")
        mock_service = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        mock_ndetails = mock.Mock()
        re.search = mock.MagicMock(return_value=search_result)
        fake_shared_data = 'fake shared data'
        network_config = self.fake_data['network_config']
        if not details_list:
            details_list = [None] * 6
            details_list[0] = fake_adapter[1]    # set MAC for matching
        if no_adapter_name:    # nothing provided in the config file
            CONF.set_override("network_adapter", None)
        else:
            CONF.set_override("network_adapter", fake_adapter[0])
        mock_osutils.get_network_adapters.return_value = [
            fake_adapter,
            # and other adapters
            ("name1", "mac1"),
            ("name2", "mac2")
        ]
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.set_static_network_config.return_value = False
        # service method setup
        methods = ["get_network_config", "get_content", "get_network_details"]
        for method in methods:
            mock_method = getattr(mock_service, method)
            mock_method.return_value = None
        if using_content == 1:
            mock_service.get_network_config.return_value = network_config
            mock_service.get_content.return_value = search_result

        elif using_content == 2:
            mock_service.get_network_details.return_value = [mock_ndetails]
        # actual tests
        if search_result is None and using_content == 1:
            self.assertRaises(exception.CloudbaseInitException,
                              self._network_plugin.execute,
                              mock_service, fake_shared_data)
            return
        if no_adapters:
            mock_osutils.get_network_adapters.return_value = []
            self.assertRaises(exception.CloudbaseInitException,
                              self._network_plugin.execute,
                              mock_service, fake_shared_data)
            return
        attrs = [
            "address",
            "netmask",
            "broadcast",
            "gateway",
            "dnsnameservers",
        ]
        if using_content == 0:
            response = self._network_plugin.execute(mock_service,
                                                    fake_shared_data)
        elif using_content == 1:
            if missing_content_path:
                mock_service.get_network_config.return_value.pop(
                    "content_path", None
                )
            response = self._network_plugin.execute(mock_service,
                                                    fake_shared_data)
            if not missing_content_path:
                mock_service.get_network_config.assert_called_once_with()
                mock_service.get_content.assert_called_once_with(
                    network_config['content_path'])
                adapters = mock_osutils.get_network_adapters()
                if CONF.network_adapter:
                    mac = [pair[1] for pair in adapters
                           if pair == fake_adapter][0]
                else:
                    mac = adapters[0][1]
                (
                    address,
                    netmask,
                    broadcast,
                    gateway,
                    dnsnameserver
                ) = map(search_result.group, attrs)
                dnsnameservers = dnsnameserver.strip().split(" ")
        elif using_content == 2:
            with self.assertRaises(exception.CloudbaseInitException):
                self._network_plugin.execute(mock_service,
                                             fake_shared_data)
            mock_service.get_network_details.reset_mock()
            mock_ndetails = service_base.NetworkDetails(*details_list)
            mock_service.get_network_details.return_value = [mock_ndetails]
            response = self._network_plugin.execute(mock_service,
                                                    fake_shared_data)
            mock_service.get_network_details.assert_called_once_with()
            mac = mock_ndetails.mac
            (
                address,
                netmask,
                broadcast,
                gateway,
                dnsnameservers
            ) = map(lambda attr: getattr(mock_ndetails, attr), attrs)
        if using_content in (1, 2) and not missing_content_path:
            mock_osutils.set_static_network_config.assert_called_once_with(
                mac,
                address,
                netmask,
                broadcast,
                gateway,
                dnsnameservers
            )
        self.assertEqual((plugin_base.PLUGIN_EXECUTION_DONE, False),
                         response)

    def test_execute(self):
        self._test_execute(using_content=1)

    def test_execute_missing_content_path(self):
        self._test_execute(using_content=1, missing_content_path=True)

    def test_execute_no_debian(self):
        self._test_execute(search_result=None, using_content=1)

    def test_execute_no_adapter_name(self):
        self._test_execute(no_adapter_name=True, using_content=1)

    def test_execute_no_adapter_name_or_adapters(self):
        self._test_execute(no_adapter_name=True, no_adapters=True,
                           using_content=1)

    def test_execute_network_details(self):
        self._test_execute(using_content=2)

    def test_execute_no_config_or_details(self):
        self._test_execute(using_content=0)
