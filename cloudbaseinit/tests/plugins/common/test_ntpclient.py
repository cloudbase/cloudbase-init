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

from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import ntpclient
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import dhcp


class NTPClientPluginTests(unittest.TestCase):

    def setUp(self):
        self._ntpclient = ntpclient.NTPClientPlugin()

    def test_set_ntp_trigger_mode(self):
        mock_osutils = mock.Mock()
        self._ntpclient._set_ntp_trigger_mode(mock_osutils)
        mock_osutils.execute_system32_process.assert_called_once_with(
            ["sc.exe", "triggerinfo", ntpclient._W32TIME_SERVICE,
             "start/networkon", "stop/networkoff"])

    @mock.patch('time.sleep')
    @mock.patch('cloudbaseinit.plugins.common.ntpclient.NTPClientPlugin.'
                '_set_ntp_trigger_mode')
    def _test_check_w32time_svc_status(self, mock_set_ntp_trigger_mode,
                                       mock_sleep, start_mode,
                                       fail_service_start,
                                       patch_check_os_version=True):
        # TODO(rtingirica): use _W32TIME_SERVICE when it will be moved outside
        # of method declaration
        mock_osutils = mock.MagicMock()
        mock_osutils.SERVICE_START_MODE_AUTOMATIC = "Automatic"
        mock_osutils.SERVICE_STATUS_RUNNING = "running"
        mock_osutils.SERVICE_STATUS_STOPPED = "stopped"
        mock_osutils.get_service_start_mode.return_value = start_mode
        mock_osutils.check_os_version.return_value = patch_check_os_version

        if fail_service_start:
            mock_osutils.get_service_status.return_value = "stopped"
            self.assertRaises(exception.CloudbaseInitException,
                              self._ntpclient._check_w32time_svc_status,
                              mock_osutils)

        else:
            mock_osutils.get_service_status.side_effect = [
                "stopped", mock_osutils.SERVICE_STATUS_RUNNING]

            self._ntpclient._check_w32time_svc_status(osutils=mock_osutils)

            if start_mode != mock_osutils.SERVICE_START_MODE_AUTOMATIC:
                mock_osutils.set_service_start_mode.assert_called_once_with(
                    ntpclient._W32TIME_SERVICE,
                    mock_osutils.SERVICE_START_MODE_AUTOMATIC)

            mock_sleep.assert_called_once_with(1)
            mock_osutils.start_service.assert_called_once_with(
                ntpclient._W32TIME_SERVICE)

        mock_osutils.get_service_start_mode.assert_called_once_with(
            ntpclient._W32TIME_SERVICE)
        mock_osutils.get_service_status.assert_called_with(
            ntpclient._W32TIME_SERVICE)

        mock_osutils.check_os_version.assert_called_once_with(6, 0)
        if patch_check_os_version:
            mock_set_ntp_trigger_mode.assert_called_once_with(mock_osutils)
        else:
            self.assertFalse(mock_set_ntp_trigger_mode.called)

    def test_check_w32time_svc_status_other_start_mode(self):
        self._test_check_w32time_svc_status(start_mode="not automatic",
                                            fail_service_start=False)

    def test_check_w32time_svc_status_start_automatic(self):
        self._test_check_w32time_svc_status(start_mode="automatic",
                                            fail_service_start=False)

    def test_check_w32time_svc_status_exception(self):
        self._test_check_w32time_svc_status(start_mode="automatic",
                                            fail_service_start=True)

    def test_check_w32time_older_oses(self):
        self._test_check_w32time_svc_status(start_mode="automatic",
                                            fail_service_start=False,
                                            patch_check_os_version=False)

    @testutils.ConfPatcher('ntp_use_dhcp_config', True)
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.utils.dhcp.get_dhcp_options')
    @mock.patch('cloudbaseinit.plugins.common.ntpclient.NTPClientPlugin.'
                '_check_w32time_svc_status')
    @mock.patch('cloudbaseinit.plugins.common.ntpclient.NTPClientPlugin.'
                '_unpack_ntp_hosts')
    def _test_execute(self, mock_unpack_ntp_hosts,
                      mock_check_w32time_svc_status,
                      mock_get_dhcp_options, mock_get_os_utils,
                      original_unpack_hosts, ntp_data, expected_hosts):
        # Set the side effect to the actual function, in order to
        # see the expected result.
        mock_unpack_ntp_hosts.side_effect = original_unpack_hosts

        mock_service = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        mock_options_data = mock.MagicMock()

        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.get_dhcp_hosts_in_use.return_value = [('fake mac address',
                                                            'fake dhcp host')]
        mock_get_dhcp_options.return_value = mock_options_data
        mock_options_data.get.return_value = ntp_data

        response = self._ntpclient.execute(service=mock_service,
                                           shared_data='fake data')

        mock_osutils.get_dhcp_hosts_in_use.assert_called_once_with()
        mock_get_dhcp_options.assert_called_once_with(
            'fake dhcp host', [dhcp.OPTION_NTP_SERVERS])
        mock_options_data.get.assert_called_once_with(dhcp.OPTION_NTP_SERVERS)
        if ntp_data:
            mock_unpack_ntp_hosts.assert_called_once_with(ntp_data)
            self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)
            mock_check_w32time_svc_status.assert_called_once_with(mock_osutils)
            mock_osutils.set_ntp_client_config.assert_called_once_with(
                expected_hosts)
        else:
            self.assertEqual((base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False),
                             response)

    def test_execute_no_ntp_options_data(self):
        self._test_execute(original_unpack_hosts=None,
                           ntp_data=None,
                           expected_hosts=None)

    def test_execute(self):
        self._test_execute(
            original_unpack_hosts=ntpclient.NTPClientPlugin._unpack_ntp_hosts,
            ntp_data=b'\xc0\xa8<\x8c',
            expected_hosts=['192.168.60.140'])
        self._test_execute(
            original_unpack_hosts=ntpclient.NTPClientPlugin._unpack_ntp_hosts,
            ntp_data=b'\xc0\xa8<\x8c\xc0\xa8<\x8e',
            expected_hosts=['192.168.60.140', '192.168.60.142'])
