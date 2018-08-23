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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
import six

from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import mtu
from cloudbaseinit.utils import dhcp


@mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
class MTUPluginTests(unittest.TestCase):

    def setUp(self):
        self._mtu = mtu.MTUPlugin()

    @mock.patch('cloudbaseinit.utils.dhcp.get_dhcp_options')
    def _test_execute(self, mock_get_os_utils,
                      mock_get_dhcp_options,
                      dhcp_options=None):
        mock_osutils = mock_get_os_utils()
        mock_osutils.get_dhcp_hosts_in_use.return_value = [
            (mock.sentinel.adapter_name1, mock.sentinel.mac_address1,
             mock.sentinel.dhcp_host1),
            (mock.sentinel.adapter_name2, mock.sentinel.mac_address2,
             mock.sentinel.dhcp_host2),
        ]

        mock_get_dhcp_options.return_value = dhcp_options

        return_value = self._mtu.execute(mock.sentinel.service,
                                         mock.sentinel.shared_data)

        expected_dhcp_calls = [
            mock.call(mock.sentinel.dhcp_host1, [dhcp.OPTION_MTU]),
            mock.call(mock.sentinel.dhcp_host2, [dhcp.OPTION_MTU]),
        ]
        expected_return_value = (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)
        self.assertEqual(expected_dhcp_calls,
                         mock_get_dhcp_options.mock_calls)
        self.assertEqual(expected_return_value,
                         return_value)

    def test_disabled_use_dhcp(self, mock_get_os_utils):
        with mock.patch('cloudbaseinit.plugins.common.'
                        'mtu.CONF') as mock_conf:
            mock_conf.mtu_use_dhcp_config = False

            self._mtu.execute(mock.sentinel.service,
                              mock.sentinel.shared_data)

            self.assertFalse(
                mock_get_os_utils().get_dhcp_hosts_in_use.called)
            self.assertFalse(
                mock_get_os_utils().set_network_adapter_mtu.called)

    def test_execute_no_data(self, mock_get_os_utils):
        for data in (None, {None: None}):
            self._test_execute(mock_get_os_utils,
                               dhcp_options=data)

        self.assertFalse(mock_get_os_utils().set_network_mtu.called)

    def test_execute_success(self, mock_get_os_utils):
        dhcp_options = {dhcp.OPTION_MTU: six.b("\x00\x04")}

        self._test_execute(mock_get_os_utils,
                           dhcp_options=dhcp_options)

        mock_osutils = mock_get_os_utils()
        mocked_calls = [
            mock.call(mock.sentinel.adapter_name1, 4),
            mock.call(mock.sentinel.adapter_name2, 4),
        ]
        self.assertEqual(
            mocked_calls,
            mock_osutils.set_network_adapter_mtu.mock_calls)
