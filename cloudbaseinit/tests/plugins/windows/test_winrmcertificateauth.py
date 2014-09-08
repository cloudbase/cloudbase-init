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

from six import moves

from cloudbaseinit.plugins import base
from cloudbaseinit.plugins import constants

from oslo.config import cfg

CONF = cfg.CONF
_ctypes_mock = mock.MagicMock()
_win32com_mock = mock.MagicMock()
_pywintypes_mock = mock.MagicMock()
mock_dict = {'ctypes': _ctypes_mock,
             'win32com': _win32com_mock,
             'pywintypes': _pywintypes_mock}


class ConfigWinRMCertificateAuthPluginTests(unittest.TestCase):
    @mock.patch.dict(sys.modules, mock_dict)
    def setUp(self):
        self.winrmcert = importlib.import_module(
            'cloudbaseinit.plugins.windows.winrmcertificateauth')
        self._certif_auth = self.winrmcert.ConfigWinRMCertificateAuthPlugin()

    def tearDown(self):
        moves.reload_module(sys)

    def _test_get_credentials(self, fake_user, fake_password):
        mock_shared_data = mock.MagicMock()
        mock_shared_data.get.side_effect = [fake_user, fake_password]
        if fake_user is None or fake_password is None:
            self.assertRaises(Exception,
                              self._certif_auth._get_credentials,
                              mock_shared_data)
        else:
            response = self._certif_auth._get_credentials(mock_shared_data)
            expected = [mock.call(constants.SHARED_DATA_USERNAME),
                        mock.call(constants.SHARED_DATA_PASSWORD)]
            self.assertEqual(mock_shared_data.get.call_args_list, expected)
            mock_shared_data.__setitem__.assert_called_once_with(
                'admin_password', None)
            self.assertEqual(response, (fake_user, fake_password))

    def test_test_get_credentials(self):
        self._test_get_credentials(fake_user='fake user',
                                   fake_password='fake password')

    def test_test_get_credentials_no_user(self):
        self._test_get_credentials(fake_user=None,
                                   fake_password='fake password')

    def test_test_get_credentials_no_password(self):
        self._test_get_credentials(fake_user='fake user',
                                   fake_password=None)

    @mock.patch('cloudbaseinit.plugins.windows.winrmcertificateauth'
                '.ConfigWinRMCertificateAuthPlugin._get_credentials')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager.'
                'import_cert')
    def _test_execute(self, mock_import_cert, mock_WinRMConfig,
                      mock_get_credentials, cert_data, cert_upn):
        mock_service = mock.MagicMock()
        mock_cert_thumprint = mock.MagicMock()
        fake_credentials = ('fake user', 'fake password')
        mock_get_credentials.return_value = fake_credentials
        mock_import_cert.return_value = (mock_cert_thumprint, cert_upn)
        mock_WinRMConfig.get_cert_mapping.return_value = True
        mock_service.get_client_auth_certs.return_value = [cert_data]

        response = self._certif_auth.execute(mock_service,
                                             shared_data='fake data')
        mock_service.get_client_auth_certs.assert_called_once_with()
        if not cert_data:
            self.assertEqual(response, (base.PLUGIN_EXECUTION_DONE, False))
        else:
            mock_get_credentials.assert_called_once_with('fake data')
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
            self.assertEqual(response, (base.PLUGIN_EXECUTION_DONE, False))

    def test_execute(self):
        cert_data = 'fake cert data'
        cert_upn = mock.MagicMock()
        self._test_execute(cert_data=cert_data, cert_upn=cert_upn)

    def test_execute_no_cert_data(self):
        cert_upn = mock.MagicMock()
        self._test_execute(cert_data=None, cert_upn=cert_upn)
