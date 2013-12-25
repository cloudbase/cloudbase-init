# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the 'License'); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import importlib
import mock
import sys
import unittest

from cloudbaseinit.openstack.common import cfg

CONF = cfg.CONF
_mock_wintypes = mock.MagicMock()
mock_dict = {'ctypes.wintypes': _mock_wintypes}


class ConfigWinRMListenerPluginTests(unittest.TestCase):
    @mock.patch.dict(sys.modules, mock_dict)
    def setUp(self):
        winrmlistener = importlib.import_module('cloudbaseinit.plugins.'
                                                'windows.winrmlistener')
        self._winrmlistener = winrmlistener.ConfigWinRMListenerPlugin()

    def _test_check_winrm_service(self, service_exists):
        mock_osutils = mock.MagicMock()
        mock_osutils.check_service_exists.return_value = service_exists
        mock_osutils.SERVICE_START_MODE_MANUAL = 'fake start'
        mock_osutils.SERVICE_START_MODE_DISABLED = 'fake start'
        mock_osutils.SERVICE_STATUS_STOPPED = 'fake status'
        mock_osutils.get_service_start_mode.return_value = 'fake start'
        mock_osutils.get_service_status.return_value = 'fake status'

        response = self._winrmlistener._check_winrm_service(mock_osutils)
        if not service_exists:
            self.assertEqual(response, False)
        else:

            mock_osutils.get_service_start_mode.assert_called_once_with(
                self._winrmlistener._winrm_service_name)
            mock_osutils.get_service_start_mode.assert_called_once_with(
                self._winrmlistener._winrm_service_name)
            mock_osutils.set_service_start_mode.assert_called_once_with(
                self._winrmlistener._winrm_service_name,
                mock_osutils .SERVICE_START_MODE_AUTOMATIC)
            mock_osutils.get_service_status.assert_called_once_with(
                self._winrmlistener._winrm_service_name)
            mock_osutils.start_service.assert_called_once_with(
                self._winrmlistener._winrm_service_name)
            self.assertEqual(response, True)

    def test_check_winrm_service(self):
        self._test_check_winrm_service(service_exists=True)

    def test_check_winrm_service_no_service(self):
        self._test_check_winrm_service(service_exists=False)

    @mock.patch('cloudbaseinit.osutils.factory.OSUtilsFactory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.windows.winrmlistener.'
                'ConfigWinRMListenerPlugin._check_winrm_service')
    @mock.patch('cloudbaseinit.plugins.windows.winrmconfig.WinRMConfig')
    @mock.patch('cloudbaseinit.plugins.windows.x509.CryptoAPICertManager'
                '.create_self_signed_cert')
    def _test_execute(self, mock_create_cert, mock_WinRMConfig,
                      mock_check_winrm_service, mock_get_os_utils,
                      service_status):
        mock_service = mock.MagicMock()
        mock_listener_config = mock.MagicMock()
        mock_cert_thumbprint = mock.MagicMock()
        shared_data = 'fake data'
        mock_osutils = mock.MagicMock()
        mock_get_os_utils.return_value = mock_osutils
        mock_check_winrm_service.return_value = service_status
        mock_create_cert.return_value = mock_cert_thumbprint
        mock_WinRMConfig().get_listener.return_value = mock_listener_config
        mock_listener_config.get.return_value = 9999

        response = self._winrmlistener.execute(mock_service, shared_data)

        mock_get_os_utils.assert_called_once_with()
        mock_check_winrm_service.assert_called_once_with(mock_osutils)

        if not service_status:
            self.assertEqual(response, (2, False))
        else:
            mock_WinRMConfig().set_auth_config.assert_called_once_with(
                basic=CONF.winrm_enable_basic_auth)
            mock_create_cert.assert_called_once_with(
                self._winrmlistener._cert_subject)

            mock_WinRMConfig().get_listener.assert_called_with(
                protocol="HTTPS")
            mock_WinRMConfig().delete_listener.assert_called_once_with(
                protocol="HTTPS")
            mock_WinRMConfig().create_listener.assert_called_once_with(
                protocol="HTTPS", cert_thumbprint=mock_cert_thumbprint)
            mock_listener_config.get.assert_called_once_with("Port")
            mock_osutils.firewall_create_rule.assert_called_once_with(
                "WinRM HTTPS", 9999, mock_osutils.PROTOCOL_TCP)
            self.assertEqual(response, (1, False))

    def test_execute(self):
        self._test_execute(service_status=True)

    def test_execute_service_status_is_false(self):
        self._test_execute(service_status=False)
