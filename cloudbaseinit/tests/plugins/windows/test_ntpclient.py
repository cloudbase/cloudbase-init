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
import unittest

from oslo.config import cfg

from cloudbaseinit import exception
from cloudbaseinit.plugins import base
from cloudbaseinit.plugins.windows import ntpclient
from cloudbaseinit.utils import dhcp

CONF = cfg.CONF


class NTPClientPluginTests(unittest.TestCase):

    def setUp(self):
        self._ntpclient = ntpclient.NTPClientPlugin()

    @mock.patch('time.sleep')
    def _test_check_w32time_svc_status(self, mock_sleep, start_mode,
                                       fail_service_start):
        # TODO(rtingirica): use _W32TIME_SERVICE when it will be moved outside
        # of method declaration
        mock_osutils = mock.MagicMock()
        mock_osutils.SERVICE_START_MODE_AUTOMATIC = "Automatic"
        mock_osutils.SERVICE_STATUS_RUNNING = "running"
        mock_osutils.SERVICE_STATUS_STOPPED = "stopped"
        mock_osutils.get_service_start_mode.return_value = start_mode

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

    def test_check_w32time_svc_status_other_start_mode(self):
        self._test_check_w32time_svc_status(start_mode="not automatic",
                                            fail_service_start=False)

    def test_check_w32time_svc_status_start_automatic(self):
        self._test_check_w32time_svc_status(start_mode="automatic",
                                            fail_service_start=False)

    def test_check_w32time_svc_status_exception(self):
        self._test_check_w32time_svc_status(start_mode="automatic",
                                            fail_service_start=True)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.utils.dhcp.get_dhcp_options')
    @mock.patch('socket.inet_ntoa')
    @mock.patch('cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin.'
                '_check_w32time_svc_status')
    def _test_execute(self, mock_check_w32time_svc_status, mock_inet_ntoa,
                      mock_get_dhcp_options, mock_get_os_utils, ntp_data):
        CONF.set_override('ntp_use_dhcp_config', True)
        mock_service = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        mock_options_data = mock.MagicMock()

        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.get_dhcp_hosts_in_use.return_value = [('fake mac address',
                                                            'fake dhcp host')]
        mock_get_dhcp_options.return_value = mock_options_data
        mock_options_data.get.return_value = ntp_data
        mock_inet_ntoa.return_value = 'fake host'

        response = self._ntpclient.execute(service=mock_service,
                                           shared_data='fake data')

        mock_osutils.get_dhcp_hosts_in_use.assert_called_once_with()
        mock_get_dhcp_options.assert_called_once_with(
            'fake dhcp host', [dhcp.OPTION_NTP_SERVERS])
        mock_options_data.get.assert_called_once_with(dhcp.OPTION_NTP_SERVERS)
        if ntp_data:
            mock_inet_ntoa.assert_called_once_with(ntp_data[:4])
            self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)
            mock_check_w32time_svc_status.assert_called_once_with(mock_osutils)
            mock_osutils.set_ntp_client_config.assert_called_once_with(
                'fake host')
        else:
            self.assertEqual((base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False),
                             response)

    def test_execute_no_ntp_options_data(self):
        self._test_execute(ntp_data=None)

    def test_execute(self):
        self._test_execute(ntp_data='ntp:fake server')
