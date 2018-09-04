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

from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import ntpclient
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import dhcp

MODULE_PATH = "cloudbaseinit.plugins.common.ntpclient"


class NTPClientPluginTests(unittest.TestCase):

    def setUp(self):
        self._ntpclient = ntpclient.NTPClientPlugin()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @testutils.ConfPatcher("real_time_clock_utc", True)
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.utils.dhcp.get_dhcp_options')
    @mock.patch(MODULE_PATH + '.NTPClientPlugin.verify_time_service')
    @mock.patch(MODULE_PATH + '.NTPClientPlugin._unpack_ntp_hosts')
    def _test_execute(self, mock_unpack_ntp_hosts,
                      mock_verify_time_service,
                      mock_get_dhcp_options, mock_get_os_utils,
                      original_unpack_hosts, ntp_data, expected_hosts,
                      is_real_time=True, enable_service=False,
                      use_dhcp_config=False):
        # Set the side effect to the actual function, in order to
        # see the expected result.
        mock_unpack_ntp_hosts.side_effect = original_unpack_hosts

        mock_service = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        mock_options_data = mock.MagicMock()

        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.get_dhcp_hosts_in_use.return_value = [(
            'fake friendly name', 'fake mac address', 'fake dhcp host')]
        mock_get_dhcp_options.return_value = mock_options_data
        mock_options_data.get.return_value = ntp_data

        expected_logging = []
        reboot_required = not is_real_time

        mock_osutils.is_real_time_clock_utc.return_value = is_real_time

        with self.snatcher:
            with testutils.ConfPatcher('ntp_enable_service', enable_service):
                with testutils.ConfPatcher('ntp_use_dhcp_config',
                                           use_dhcp_config):
                    response = self._ntpclient.execute(
                        service=mock_service,
                        shared_data=mock.sentinel.shared_data)

        mock_get_os_utils.assert_called_once_with()
        mock_osutils.is_real_time_clock_utc.assert_called_once_with()
        if not is_real_time:
            mock_osutils.set_real_time_clock_utc.assert_called_once_with(
                True)
            expected_logging.append('RTC set to UTC: %s' % is_real_time)
        if enable_service:
            mock_verify_time_service.assert_called_once_with(mock_osutils)
            expected_logging.append('NTP client service enabled')
        if use_dhcp_config:
            mock_osutils.get_dhcp_hosts_in_use.assert_called_once_with()
            mock_get_dhcp_options.assert_called_once_with(
                'fake dhcp host', [dhcp.OPTION_NTP_SERVERS])
            mock_options_data.get.assert_called_once_with(
                dhcp.OPTION_NTP_SERVERS)
            if ntp_data:
                mock_unpack_ntp_hosts.assert_called_once_with(ntp_data)
                self.assertEqual(response,
                                 (base.PLUGIN_EXECUTION_DONE, reboot_required))
                mock_osutils.set_ntp_client_config.assert_called_once_with(
                    expected_hosts)
            else:
                expected_logging.append(
                    "Could not obtain the NTP configuration via DHCP")
                self.assertEqual(
                    response,
                    (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, reboot_required))
        else:
            self.assertEqual(response,
                             (base.PLUGIN_EXECUTION_DONE, reboot_required))

    def test_execute_is_not_real_time(self):
        self._test_execute(
            original_unpack_hosts=ntpclient.NTPClientPlugin._unpack_ntp_hosts,
            ntp_data=b'\xc0\xa8<\x8c',
            expected_hosts=['192.168.60.140'],
            is_real_time=False)

    def test_execute_enable_ntp_service(self):
        self._test_execute(
            original_unpack_hosts=ntpclient.NTPClientPlugin._unpack_ntp_hosts,
            ntp_data=b'\xc0\xa8<\x8c',
            expected_hosts=['192.168.60.140'],
            enable_service=True)

    def test_execute_use_dhcp_config_has_ntp_option_data(self):
        self._test_execute(
            original_unpack_hosts=ntpclient.NTPClientPlugin._unpack_ntp_hosts,
            ntp_data=b'\xc0\xa8<\x8c',
            expected_hosts=['192.168.60.140'],
            use_dhcp_config=True)

    def test_execute_no_ntp_options_data(self):
        self._test_execute(original_unpack_hosts=None,
                           ntp_data=None,
                           expected_hosts=None,
                           use_dhcp_config=True)

    def test_execute_no_dhcp_config(self):
        self._test_execute(
            original_unpack_hosts=None,
            ntp_data=None, expected_hosts=None,
            use_dhcp_config=False)
