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

from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import constants
from cloudbaseinit.tests import testutils


class ConfigWinRMCertificateAuthPluginTests(unittest.TestCase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()
        self._win32com_mock = mock.MagicMock()
        self._pywintypes_mock = mock.MagicMock()
        self._moves_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._ctypes_mock,
             'win32com': self._win32com_mock,
             'pywintypes': self._pywintypes_mock,
             'six.moves': self._moves_mock})

        self._module_patcher.start()

        self._winreg_mock = self._moves_mock.winreg

        self.winrmcert = importlib.import_module(
            'cloudbaseinit.plugins.windows.winrmcertificateauth')
        self._certif_auth = self.winrmcert.ConfigWinRMCertificateAuthPlugin()

    def tearDown(self):
        self._module_patcher.stop()

    @testutils.ConfPatcher('username', '')
    def test_get_credentials_no_username(self):
        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self._certif_auth._get_credentials(mock.sentinel.service, {})

        expected_message = (
            "Cannot execute plugin as the username has not been set in "
            "the plugins shared data, nor it was found in config file.")
        self.assertEqual(expected_message, str(cm.exception))

    def test_get_credentials_no_password(self):
        mock_service = mock.Mock()
        mock_service.get_admin_password.return_value = None

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self._certif_auth._get_credentials(mock_service, {})

        expected_message = (
            "Cannot execute plugin as the password has not been set "
            "in the plugins shared data, nor it was retrieved "
            "from the metadata service.")
        self.assertEqual(expected_message, str(cm.exception))
        mock_service.get_admin_password.assert_called_once_with()

    def test_get_credentials_get_admin_password(self):
        mock_service = mock.Mock()
        mock_service.get_admin_password.return_value = mock.sentinel.password
        shared_data = {constants.SHARED_DATA_USERNAME: mock.sentinel.username}

        result = self._certif_auth._get_credentials(mock_service, shared_data)

        self.assertIsNone(shared_data[constants.SHARED_DATA_PASSWORD])
        self.assertEqual((mock.sentinel.username, mock.sentinel.password),
                         result)
        mock_service.get_admin_password.assert_called_once_with()

    @mock.patch('cloudbaseinit.plugins.windows.winrmcertificateauth'
                '.ConfigWinRMCertificateAuthPlugin._get_credentials')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager.'
                'import_cert')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.utils.windows.security.WindowsSecurityUtils'
                '.set_uac_remote_restrictions')
    @mock.patch('cloudbaseinit.utils.windows.security.WindowsSecurityUtils'
                '.get_uac_remote_restrictions')
    def _test_execute(self, get_uac_rs, set_uac_rs, mock_get_os_utils,
                      mock_import_cert, mock_WinRMConfig,
                      mock_get_credentials, cert_data, cert_upn):
        mock_osutils = mock.MagicMock()
        mock_service = mock.MagicMock()
        mock_cert_thumprint = mock.MagicMock()
        fake_credentials = ('fake user', 'fake password')
        mock_get_credentials.return_value = fake_credentials

        mock_import_cert.return_value = (mock_cert_thumprint, cert_upn)
        mock_WinRMConfig.get_cert_mapping.return_value = True
        mock_service.get_client_auth_certs.return_value = [cert_data]

        mock_get_os_utils.return_value = mock_osutils

        expected_set_token_calls = [mock.call(enable=False),
                                    mock.call(enable=True)]

        mock_osutils.check_os_version.side_effect = [True, False]
        get_uac_rs.return_value = True

        expected_check_version_calls = [mock.call(6, 0), mock.call(6, 2)]

        response = self._certif_auth.execute(mock_service,
                                             shared_data='fake data')

        if not cert_data:
            self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)
        else:
            mock_service.get_client_auth_certs.assert_called_once_with()
            self.assertEqual(expected_check_version_calls,
                             mock_osutils.check_os_version.call_args_list)
            mock_get_os_utils.assert_called_once_with()
            self.assertEqual(expected_set_token_calls,
                             set_uac_rs.call_args_list)

            mock_get_credentials.assert_called_once_with(
                mock_service, 'fake data')
            mock_import_cert.assert_called_once_with(
                cert_data, store_name=self.winrmcert.x509.STORE_NAME_ROOT)

            mock_WinRMConfig().set_auth_config.assert_called_once_with(
                certificate=True)
            mock_WinRMConfig().get_cert_mapping.assert_called_once_with(
                mock_cert_thumprint, cert_upn)
            mock_WinRMConfig().delete_cert_mapping.assert_called_once_with(
                mock_cert_thumprint, cert_upn)
            mock_WinRMConfig().create_cert_mapping.assert_called_once_with(
                mock_cert_thumprint, cert_upn, 'fake user',
                'fake password')
            self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute(self):
        cert_data = 'fake cert data'
        cert_upn = mock.MagicMock()
        self._test_execute(cert_data=cert_data, cert_upn=cert_upn)

    def test_execute_no_cert_data(self):
        cert_upn = mock.MagicMock()
        self._test_execute(cert_data=None, cert_upn=cert_upn)
