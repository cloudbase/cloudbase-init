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
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class ConfigWinRMListenerPluginTests(unittest.TestCase):

    def setUp(self):
        self._mock_wintypes = mock.MagicMock()
        self._mock_pywintypes = mock.MagicMock()
        self._mock_win32 = mock.MagicMock()
        self._moves_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._mock_wintypes,
             'ctypes.wintypes': self._mock_wintypes,
             'pywintypes': self._mock_pywintypes,
             'win32com': self._mock_win32,
             'six.moves': self._moves_mock})
        self._module_patcher.start()
        self._winreg_mock = self._moves_mock.winreg

        winrmlistener = importlib.import_module('cloudbaseinit.plugins.'
                                                'windows.winrmlistener')
        self._winrmlistener = winrmlistener.ConfigWinRMListenerPlugin()

    def tearDown(self):
        self._module_patcher.stop()

    def _test_check_winrm_service(self, service_exists):
        mock_osutils = mock.MagicMock()
        mock_osutils.check_service_exists.return_value = service_exists
        mock_osutils.SERVICE_START_MODE_MANUAL = 'fake start'
        mock_osutils.SERVICE_START_MODE_DISABLED = 'fake start'
        mock_osutils.SERVICE_STATUS_STOPPED = 'fake status'
        mock_osutils.get_service_start_mode.return_value = 'fake start'
        mock_osutils.get_service_status.return_value = 'fake status'

        with testutils.LogSnatcher('cloudbaseinit.plugins.windows.'
                                   'winrmlistener') as snatcher:
            response = self._winrmlistener._check_winrm_service(mock_osutils)

        if not service_exists:
            expected_logging = [
                "Cannot configure the WinRM listener as the service "
                "is not available"
            ]
            self.assertEqual(expected_logging, snatcher.output)
            self.assertFalse(response)
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
            self.assertTrue(response)

    def test_check_winrm_service(self):
        self._test_check_winrm_service(service_exists=True)

    def test_check_winrm_service_no_service(self):
        self._test_check_winrm_service(service_exists=False)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.windows.winrmlistener.'
                'ConfigWinRMListenerPlugin._check_winrm_service')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '.create_self_signed_cert')
    @mock.patch('cloudbaseinit.utils.windows.security.WindowsSecurityUtils'
                '.set_uac_remote_restrictions')
    @mock.patch('cloudbaseinit.utils.windows.security.WindowsSecurityUtils'
                '.get_uac_remote_restrictions')
    def _test_execute(self, get_uac_rs, set_uac_rs, mock_create_cert,
                      mock_WinRMConfig,
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

        mock_osutils.check_os_version.side_effect = [True, False]
        get_uac_rs.return_value = True

        expected_check_version_calls = [mock.call(6, 0), mock.call(6, 2)]
        expected_set_token_calls = [mock.call(enable=False),
                                    mock.call(enable=True)]

        response = self._winrmlistener.execute(mock_service, shared_data)

        mock_get_os_utils.assert_called_once_with()
        mock_check_winrm_service.assert_called_once_with(mock_osutils)

        if not service_status:
            self.assertEqual((base.PLUGIN_EXECUTE_ON_NEXT_BOOT,
                              service_status), response)
        else:
            self.assertEqual(expected_check_version_calls,
                             mock_osutils.check_os_version.call_args_list)
            self.assertEqual(expected_set_token_calls,
                             set_uac_rs.call_args_list)
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
            self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute(self):
        self._test_execute(service_status=True)

    def test_execute_service_status_is_false(self):
        self._test_execute(service_status=False)
