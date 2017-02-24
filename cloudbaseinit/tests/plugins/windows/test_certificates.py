# Copyright 2017 Cloudbase Solutions Srl
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

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


class ServerCertificatesPluginTests(unittest.TestCase):
    def setUp(self):
        module_path = 'cloudbaseinit.plugins.windows.certificates'
        self.snatcher = testutils.LogSnatcher(module_path)

        self._ctypes_mock = mock.MagicMock()
        self._comtypes_mock = mock.MagicMock()
        self._ctypes_mock_ = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'comtypes': self._comtypes_mock,
             'ctypes': self._ctypes_mock,
             'ctypes.windll': self._ctypes_mock_})

        self._module_patcher.start()
        self.addCleanup(self._module_patcher.stop)

        self.cert_module = importlib.import_module(module_path)
        self._cert = self.cert_module.ServerCertificatesPlugin()

    @mock.patch.object(constant, 'CERT_LOCATION_LOCAL_MACHINE',
                       mock.sentinel.CERT_LOCATION_LOCAL_MACHINE,
                       create=True)
    @mock.patch.object(constant, 'CERT_LOCATION_CURRENT_USER',
                       mock.sentinel.CERT_LOCATION_CURRENT_USER,
                       create=True)
    def _test_use_machine_keyset(self, store_location):
        if store_location == constant.CERT_LOCATION_LOCAL_MACHINE:
            expected_result = True
        elif store_location == constant.CERT_LOCATION_CURRENT_USER:
            expected_result = False
        else:
            ex = exception.ItemNotFoundException(
                "Unsupported certificate store location: %s" %
                store_location)
            with self.assertRaises(exception.ItemNotFoundException) as exc:
                (self._cert._use_machine_keyset(store_location))
            self.assertEqual(str(ex), str(exc.exception))
            return

        result = (self._cert._use_machine_keyset(store_location))
        self.assertEqual(result, expected_result)

    def test_use_keyset_current_user(self):
        store_location = mock.sentinel.CERT_LOCATION_CURRENT_USER
        self._test_use_machine_keyset(store_location)

    def test_use_keyset_local_machine(self):
        store_location = mock.sentinel.CERT_LOCATION_LOCAL_MACHINE
        self._test_use_machine_keyset(store_location)

    def test_use_keyset_except(self):
        self._test_use_machine_keyset(None)

    def test_get_os_requirements(self):
        result = self._cert.get_os_requirements()
        self.assertEqual(result, ('win32', (5, 2)))

    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager')
    def _test_execute(self, mock_crypto_manager, certs_info=None):
        mock_service = mock.Mock()
        mock_service.get_server_certs.return_value = certs_info
        self._cert._use_machine_keyset = mock.Mock()
        if certs_info is None:
            expected_logging = [
                "The metadata service does not provide server "
                "certificates"
            ]
            call_count = 0
        else:
            call_count = len(certs_info)
            cert_info = certs_info[0]
            cert_name = cert_info.get("name")
            store_location = cert_info.get("store_location")
            store_name = cert_info.get("store_name")
            expected_logging = [
                "Importing PFX certificate {cert_name} in store "
                "{store_location}, {store_name}".format(
                    cert_name=cert_name,
                    store_location=store_location,
                    store_name=store_name)
            ] * call_count
        with self.snatcher:
            result = self._cert.execute(
                mock_service, mock.sentinel.shared_data)
        self.assertEqual(expected_logging, self.snatcher.output)
        self.assertEqual(result,
                         (self.cert_module.base.PLUGIN_EXECUTION_DONE, False))
        self.assertEqual(mock_crypto_manager.return_value.
                         import_pfx_certificate.call_count, call_count)
        self.assertEqual(self._cert._use_machine_keyset.call_count, call_count)

    def test_execute_no_certs(self):
        self._test_execute()

    def test_execute(self):
        cert_info = {
            "name": "fake_name",
            "store_location": "fake store_location",
            "store_name": "fake store_name",
            "pfx_data": "fake pfx_data"
        }
        certs_info = [cert_info] * 5
        self._test_execute(certs_info=certs_info)
