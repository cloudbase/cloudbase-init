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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.plugins.windows import ntpclient

CONF = cloudbaseinit_conf.CONF


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
    @mock.patch('cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin.'
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
                              self._ntpclient.verify_time_service,
                              mock_osutils)

        else:
            mock_osutils.get_service_status.side_effect = [
                "stopped", mock_osutils.SERVICE_STATUS_RUNNING]

            self._ntpclient.verify_time_service(osutils=mock_osutils)

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

        mock_osutils.check_os_version.assert_called_once_with(6, 1)
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
