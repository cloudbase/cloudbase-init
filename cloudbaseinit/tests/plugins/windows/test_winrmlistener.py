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
             'six.moves': self._moves_mock
             })
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

    @mock.patch('cloudbaseinit.utils.windows.security.'
                'WindowsSecurityUtils')
    def _test_check_uac_remote_restrictions(self, mock_SecurityUtils,
                                            disable_uac_remote_restrictions):
        mock_security_utils = mock.MagicMock()
        mock_SecurityUtils.return_value = mock_security_utils
        mock_osutils = mock.Mock()
        mock_osutils.check_os_version.side_effect = [True, False]
        if disable_uac_remote_restrictions:
            mock_security_utils.get_uac_remote_restrictions.return_value = \
                disable_uac_remote_restrictions

        with self._winrmlistener._check_uac_remote_restrictions(mock_osutils):
            mock_SecurityUtils.assert_called_once_with()
            mock_osutils.check_os_version.assert_has_calls(
                [mock.call(6, 0), mock.call(6, 2)])
            (mock_security_utils.get_uac_remote_restrictions.
             assert_called_once_with())
            if disable_uac_remote_restrictions:
                expected_set_token_calls = [mock.call(enable=True)]
            else:
                expected_set_token_calls = [mock.call(enable=False),
                                            mock.call(enable=True)]
            mock_security_utils.set_uac_remote_restrictions.has_calls(
                expected_set_token_calls)

    def test_check_uac_remote_restrictions(self):
        self._test_check_uac_remote_restrictions(
            disable_uac_remote_restrictions=True)

    def test_check_uac_remote_restrictions_no_disable_restrictions(self):
        self._test_check_uac_remote_restrictions(
            disable_uac_remote_restrictions=False)

    def _test_configure_winrm_listener(self, has_listener=True):
        mock_listener_config = mock.MagicMock()
        mock_winrm_config = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        mock_osutils.PROTOCOL_TCP = mock.sentinel.PROTOCOL_TCP
        mock_winrm_config.get_listener.side_effect = [
            has_listener, mock_listener_config]
        port = 9999
        protocol = mock.sentinel.protocol
        cert_thumbprint = mock.sentinel.cert_thumbprint
        mock_listener_config.get.return_value = port

        self._winrmlistener._configure_winrm_listener(
            mock_osutils, mock_winrm_config, protocol, cert_thumbprint)

        if has_listener:
            mock_winrm_config.delete_listener.assert_called_once_with(
                protocol=protocol)
        mock_winrm_config.create_listener.assert_called_once_with(
            cert_thumbprint=cert_thumbprint, protocol=protocol)
        mock_listener_config.get.assert_called_once_with("Port")
        mock_osutils.firewall_create_rule.assert_called_once_with(
            "WinRM %s" % protocol, port, mock_osutils.PROTOCOL_TCP)

    def test_configure_winrm_listener(self):
        self._test_configure_winrm_listener()

    def test_configure_winrm_listener_no_initial_listener(self):
        self._test_configure_winrm_listener(has_listener=False)

    def _test_get_winrm_listeners_config(self, listeners_config=None,
                                         http_listener=None,
                                         https_listener=None):
        winrmconfig = importlib.import_module('cloudbaseinit.utils.'
                                              'windows.winrmconfig')
        mock_service = mock.MagicMock()
        mock_service.get_winrm_listeners_configuration.return_value = \
            listeners_config
        expected_result = listeners_config
        if listeners_config is None:
            expected_result = []
            if http_listener:
                expected_result.append(
                    {"protocol": winrmconfig.LISTENER_PROTOCOL_HTTP})
            if https_listener:
                expected_result.append(
                    {"protocol": winrmconfig.LISTENER_PROTOCOL_HTTPS})

        with testutils.ConfPatcher("winrm_configure_http_listener",
                                   http_listener):
            with testutils.ConfPatcher("winrm_configure_https_listener",
                                       https_listener):
                result = self._winrmlistener._get_winrm_listeners_config(
                    mock_service)

        self.assertEqual(result, expected_result)

    def test_get_winrm_listeners_config_has_listeners(self):
        self._test_get_winrm_listeners_config(
            listeners_config=mock.sentinel.listeners)

    def test_get_winrm_listeners_config_http_listener(self):
        self._test_get_winrm_listeners_config(http_listener=True)

    def test_get_winrm_listeners_config_https_listener(self):
        self._test_get_winrm_listeners_config(https_listener=True)

    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager')
    def test_create_self_signed_certificate(self, mock_CryptoAPICertManager):
        mock_cert_mgr = mock.MagicMock()
        mock_CryptoAPICertManager.return_value = mock_cert_mgr
        mock_cert_mgr.create_self_signed_cert.return_value = \
            mock.sentinel.cert_thumbprint, mock.sentinel.cert_str
        result = self._winrmlistener._create_self_signed_certificate()
        self.assertEqual(result, mock.sentinel.cert_thumbprint)
        mock_CryptoAPICertManager.assert_called_once_with()
        mock_cert_mgr.create_self_signed_cert.assert_called_once_with(
            self._winrmlistener._cert_subject)

    @mock.patch('cloudbaseinit.plugins.windows.winrmlistener.'
                'ConfigWinRMListenerPlugin._configure_winrm_listener')
    @mock.patch('cloudbaseinit.plugins.windows.winrmlistener.'
                'ConfigWinRMListenerPlugin._check_uac_remote_restrictions')
    @mock.patch('cloudbaseinit.plugins.windows.winrmlistener.'
                'ConfigWinRMListenerPlugin._get_winrm_listeners_config')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.windows.winrmlistener.'
                'ConfigWinRMListenerPlugin._check_winrm_service')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig')
    @mock.patch('cloudbaseinit.plugins.windows.winrmlistener'
                '.ConfigWinRMListenerPlugin._create_self_signed_certificate')
    def _test_execute(self, mock_create_cert, mock_WinRMConfig,
                      mock_check_winrm_service, mock_get_os_utils,
                      mock_get_winrm_listeners, mock_check_restrictions,
                      mock_configure_listener,
                      service_status=True, protocol=None,
                      listeners_config=True, certificate_thumbprint=None):
        mock_winrm_config = mock.MagicMock()
        mock_WinRMConfig.return_value = mock_winrm_config
        mock_osutils = mock.MagicMock()
        mock_get_os_utils.return_value = mock_osutils
        mock_check_winrm_service.return_value = service_status
        if not service_status:
            expected_result = (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)
        elif not listeners_config:
            mock_get_winrm_listeners.return_value = None
            expected_result = (base.PLUGIN_EXECUTION_DONE, False)
        else:
            expected_result = (base.PLUGIN_EXECUTION_DONE, False)
            if certificate_thumbprint is not None:
                certificate_thumbprint = \
                    str(mock.sentinel.certificate_thumbprint)
            listener_config = {
                "protocol": protocol,
                "certificate_thumbprint": certificate_thumbprint
            }
            mock_get_winrm_listeners.return_value = [listener_config]
        winrm_enable_basic_auth = mock.Mock(spec=bool)
        with testutils.ConfPatcher('winrm_enable_basic_auth',
                                   winrm_enable_basic_auth):
            result = self._winrmlistener.execute(
                mock.sentinel.service, mock.sentinel.shared_data)

        self.assertEqual(result, expected_result)
        mock_get_os_utils.assert_called_once_with()
        mock_check_winrm_service.assert_called_once_with(mock_osutils)
        if service_status:
            mock_get_winrm_listeners.assert_called_once_with(
                mock.sentinel.service)
            if listeners_config:
                mock_check_restrictions.assert_called_once_with(mock_osutils)
                mock_WinRMConfig.assert_called_once_with()
                mock_winrm_config.set_auth_config.assert_called_once_with(
                    basic=winrm_enable_basic_auth)
                winrmconfig = importlib.import_module('cloudbaseinit.utils.'
                                                      'windows.winrmconfig')
                if (protocol == winrmconfig.LISTENER_PROTOCOL_HTTPS and
                        not certificate_thumbprint):
                    certificate_thumbprint = mock_create_cert.return_value
                    mock_create_cert.assert_called_once_with()
                mock_configure_listener.assert_called_once_with(
                    mock_osutils, mock_winrm_config, protocol.upper(),
                    certificate_thumbprint)

    def test_execute_service_status_is_false(self):
        self._test_execute(service_status=False)

    def test_execute_no_listeners_config(self):
        self._test_execute(listeners_config=None)

    def test_execute_http_protocol(self):
        self._test_execute(protocol=str(mock.sentinel.http))

    def test_execute_https_protocol(self):
        self._test_execute(protocol="HTTPS")
