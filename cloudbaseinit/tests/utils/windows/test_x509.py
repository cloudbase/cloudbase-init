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
import six
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.utils import x509constants


class CryptoAPICertManagerTests(unittest.TestCase):

    def setUp(self):
        self._ctypes = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules', {'ctypes': self._ctypes})

        self._module_patcher.start()

        self.x509 = importlib.import_module("cloudbaseinit.utils.windows.x509")
        self._x509_manager = self.x509.CryptoAPICertManager()

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('cloudbaseinit.utils.windows.x509.free')
    @mock.patch('cloudbaseinit.utils.windows.x509.malloc')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertGetCertificateContextProperty')
    def _test_get_cert_thumprint(self, mock_CertGetCertificateContextProperty,
                                 mock_malloc, mock_free, ret_val):
        mock_DWORD = self._ctypes.wintypes.DWORD
        mock_CSIZET = self._ctypes.c_size_t
        mock_cast = self._ctypes.cast
        mock_POINTER = self._ctypes.POINTER
        mock_byref = self._ctypes.byref

        mock_pointer = mock.MagicMock()
        fake_cert_context_p = 'fake context'
        mock_DWORD.return_value.value = 10
        mock_CSIZET.return_value.value = mock_DWORD.return_value.value
        mock_CertGetCertificateContextProperty.return_value = ret_val
        mock_POINTER.return_value = mock_pointer
        mock_cast.return_value.contents = [16]

        if not ret_val:
            self.assertRaises(self.x509.cryptoapi.CryptoAPIException,
                              self._x509_manager._get_cert_thumprint,
                              fake_cert_context_p)
        else:
            expected = [mock.call(fake_cert_context_p,
                                  self.x509.cryptoapi.CERT_SHA1_HASH_PROP_ID,
                                  None, mock_byref.return_value),
                        mock.call(fake_cert_context_p,
                                  self.x509.cryptoapi.CERT_SHA1_HASH_PROP_ID,
                                  mock_malloc.return_value,
                                  mock_byref.return_value)]

            response = self._x509_manager._get_cert_thumprint(
                fake_cert_context_p)

            self.assertEqual(
                expected,
                mock_CertGetCertificateContextProperty.call_args_list)

            mock_malloc.assert_called_with(mock_CSIZET.return_value)
            mock_cast.assert_called_with(mock_malloc(), mock_pointer)
            mock_free.assert_called_with(mock_malloc())
            self.assertEqual('10', response)

    def test_get_cert_thumprint(self):
        self._test_get_cert_thumprint(ret_val=True)

    def test_get_cert_thumprint_GetCertificateContextProperty_exception(self):
        self._test_get_cert_thumprint(ret_val=False)

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptDestroyKey')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptReleaseContext')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptGenKey')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptAcquireContext')
    def _test_generate_key(self, mock_CryptAcquireContext, mock_CryptGenKey,
                           mock_CryptReleaseContext, mock_CryptDestroyKey,
                           acquired_context, generate_key_ret_val):

        mock_HANDLE = self._ctypes.wintypes.HANDLE
        mock_byref = self._ctypes.byref

        mock_CryptAcquireContext.return_value = acquired_context
        mock_CryptGenKey.return_value = generate_key_ret_val

        if not acquired_context:
            self.assertRaises(self.x509.cryptoapi.CryptoAPIException,
                              self._x509_manager._generate_key,
                              'fake container', True)
        else:
            if not generate_key_ret_val:
                self.assertRaises(self.x509.cryptoapi.CryptoAPIException,
                                  self._x509_manager._generate_key,
                                  'fake container', True)
            else:
                self._x509_manager._generate_key('fake container', True)

                mock_CryptAcquireContext.assert_called_with(
                    mock_byref(), 'fake container', None,
                    self.x509.cryptoapi.PROV_RSA_FULL,
                    self.x509.cryptoapi.CRYPT_MACHINE_KEYSET)
                mock_CryptGenKey.assert_called_with(
                    mock_HANDLE(), self.x509.cryptoapi.AT_SIGNATURE,
                    0x08000000, mock_HANDLE())
                mock_CryptDestroyKey.assert_called_once_with(
                    mock_HANDLE())
                mock_CryptReleaseContext.assert_called_once_with(
                    mock_HANDLE(), 0)

    def test_generate_key(self):
        self._test_generate_key(acquired_context=True,
                                generate_key_ret_val='fake key')

    def test_generate_key_GetCertificateContextProperty_exception(self):
        self._test_generate_key(acquired_context=False,
                                generate_key_ret_val='fake key')

    def test_generate_key_CryptGenKey_exception(self):
        self._test_generate_key(acquired_context=True,
                                generate_key_ret_val=None)

    @mock.patch('cloudbaseinit.utils.windows.x509.free')
    @mock.patch('cloudbaseinit.utils.windows.x509.malloc')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._add_system_time_interval')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._generate_key')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._get_cert_thumprint')
    @mock.patch('uuid.uuid4')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertStrToName')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CRYPTOAPI_BLOB')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CRYPT_KEY_PROV_INFO')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CRYPT_ALGORITHM_IDENTIFIER')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'SYSTEMTIME')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'GetSystemTime')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertCreateSelfSignCertificate')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertAddEnhancedKeyUsageIdentifier')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertOpenStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertAddCertificateContextToStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertCloseStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertFreeCertificateContext')
    def _test_create_self_signed_cert(self, mock_CertFreeCertificateContext,
                                      mock_CertCloseStore,
                                      mock_CertAddCertificateContextToStore,
                                      mock_CertOpenStore,
                                      mock_CertAddEnhancedKeyUsageIdentifier,
                                      mock_CertCreateSelfSignCertificate,
                                      mock_GetSystemTime, mock_SYSTEMTIME,
                                      mock_CRYPT_ALGORITHM_IDENTIFIER,
                                      mock_CRYPT_KEY_PROV_INFO,
                                      mock_CRYPTOAPI_BLOB,
                                      mock_CertStrToName,
                                      mock_uuid4, mock_get_cert_thumprint,
                                      mock_generate_key,
                                      mock_add_system_time_interval,
                                      mock_malloc, mock_free, certstr,
                                      certificate, enhanced_key, store_handle,
                                      context_to_store):

        mock_POINTER = self._ctypes.POINTER
        mock_byref = self._ctypes.byref
        mock_cast = self._ctypes.cast

        mock_uuid4.return_value = 'fake_name'
        mock_CertCreateSelfSignCertificate.return_value = certificate
        mock_CertAddEnhancedKeyUsageIdentifier.return_value = enhanced_key
        mock_CertStrToName.return_value = certstr
        mock_CertOpenStore.return_value = store_handle
        mock_CertAddCertificateContextToStore.return_value = context_to_store
        if (certstr is None or certificate is None or enhanced_key is None
                or store_handle is None or context_to_store is None):
            self.assertRaises(self.x509.cryptoapi.CryptoAPIException,
                              self._x509_manager.create_self_signed_cert,
                              'fake subject', 10, True,
                              self.x509.STORE_NAME_MY)
        else:
            response = self._x509_manager.create_self_signed_cert(
                subject='fake subject')
            mock_cast.assert_called_with(mock_malloc(), mock_POINTER())
            mock_CRYPTOAPI_BLOB.assert_called_once_with()
            mock_CRYPT_KEY_PROV_INFO.assert_called_once_with()
            mock_CRYPT_ALGORITHM_IDENTIFIER.assert_called_once_with()
            mock_SYSTEMTIME.assert_called_once_with()
            mock_GetSystemTime.assert_called_once_with(mock_byref())
            mock_CertCreateSelfSignCertificate.assert_called_once_with(
                None, mock_byref(), 0, mock_byref(),
                mock_byref(), mock_byref(), mock_byref(), None)
            mock_CertAddEnhancedKeyUsageIdentifier.assert_called_with(
                mock_CertCreateSelfSignCertificate(),
                self.x509.cryptoapi.szOID_PKIX_KP_SERVER_AUTH)
            mock_CertOpenStore.assert_called_with(
                self.x509.cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0,
                self.x509.cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE,
                six.text_type(self.x509.STORE_NAME_MY))
            mock_get_cert_thumprint.assert_called_once_with(
                mock_CertCreateSelfSignCertificate())
            mock_add_system_time_interval.assert_has_calls(
                [mock.call(mock_SYSTEMTIME.return_value,
                           self.x509.X509_END_DATE_INTERVAL),
                 mock.call(mock_SYSTEMTIME.return_value,
                           self.x509.X509_START_DATE_INTERVAL)])
            mock_CertCloseStore.assert_called_once_with(store_handle, 0)
            mock_CertFreeCertificateContext.assert_called_once_with(
                mock_CertCreateSelfSignCertificate())
            mock_free.assert_called_once_with(mock_cast())

            self.assertEqual(mock_get_cert_thumprint.return_value, response)

        mock_generate_key.assert_called_once_with('fake_name', True)

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'SYSTEMTIME')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'FILETIME')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'SystemTimeToFileTime')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'FileTimeToSystemTime')
    def test_add_system_time_interval(self, mock_FileTimeToSystemTime,
                                      mock_SystemTimeToFileTime,
                                      mock_FILETIME, mock_SYSTEMTIME):
        mock_system_time = mock.MagicMock()
        fake_increment = 1
        mock_byref = self._ctypes.byref

        new_system_time = self._x509_manager._add_system_time_interval(
            mock_system_time, fake_increment)

        mock_FILETIME.assert_called_once_with()
        mock_SystemTimeToFileTime.assert_called_once_with(mock_byref(),
                                                          mock_byref())
        mock_SYSTEMTIME.assert_called_once_with()
        mock_FileTimeToSystemTime.assert_called_once_with(mock_byref(),
                                                          mock_byref())
        self.assertEqual(mock_SYSTEMTIME.return_value, new_system_time)

    def test_create_self_signed_cert(self):
        self._test_create_self_signed_cert(certstr='fake cert name',
                                           certificate='fake certificate',
                                           enhanced_key='fake key',
                                           store_handle='fake handle',
                                           context_to_store='fake context')

    def test_create_self_signed_cert_CertStrToName_fail(self):
        self._test_create_self_signed_cert(certstr=None,
                                           certificate='fake certificate',
                                           enhanced_key='fake key',
                                           store_handle='fake handle',
                                           context_to_store='fake context')

    def test_create_self_signed_cert_CertCreateSelfSignCertificate_fail(self):
        self._test_create_self_signed_cert(certstr='fake cert name',
                                           certificate=None,
                                           enhanced_key='fake key',
                                           store_handle='fake handle',
                                           context_to_store='fake context')

    def test_create_self_signed_cert_AddEnhancedKeyUsageIdentifier_fail(self):
        self._test_create_self_signed_cert(certstr='fake cert name',
                                           certificate='fake certificate',
                                           enhanced_key=None,
                                           store_handle='fake handle',
                                           context_to_store='fake context')

    def test_create_self_signed_cert_CertOpenStore_fail(self):
        self._test_create_self_signed_cert(certstr='fake cert name',
                                           certificate='fake certificate',
                                           enhanced_key='fake key',
                                           store_handle=None,
                                           context_to_store='fake context')

    def test_create_self_signed_cert_AddCertificateContextToStore_fail(self):
        self._test_create_self_signed_cert(certstr='fake cert name',
                                           certificate='fake certificate',
                                           enhanced_key='fake key',
                                           store_handle='fake handle',
                                           context_to_store=None)

    def test_get_cert_base64(self):
        fake_cert_data = ''
        fake_cert_data += x509constants.PEM_HEADER + '\n'
        fake_cert_data += 'fake cert' + '\n'
        fake_cert_data += x509constants.PEM_FOOTER

        response = self._x509_manager._get_cert_base64(fake_cert_data)
        self.assertEqual('fake cert', response)

    @mock.patch('cloudbaseinit.utils.windows.x509.free')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._get_cert_thumprint')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertCloseStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertFreeCertificateContext')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertGetNameString')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertAddEncodedCertificateToStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertOpenStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CryptStringToBinaryW')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._get_cert_base64')
    @mock.patch('cloudbaseinit.utils.windows.x509.malloc')
    def _test_import_cert(self, mock_malloc, mock_get_cert_base64,
                          mock_CryptStringToBinaryW, mock_CertOpenStore,
                          mock_CertAddEncodedCertificateToStore,
                          mock_CertGetNameString,
                          mock_CertFreeCertificateContext,
                          mock_CertCloseStore, mock_get_cert_thumprint,
                          mock_free, crypttstr, store_handle, add_enc_cert,
                          upn_len):
        mock_POINTER = self._ctypes.POINTER
        mock_cast = self._ctypes.cast
        mock_byref = self._ctypes.byref
        mock_DWORD = self._ctypes.wintypes.DWORD

        mock_create_unicode_buffer = self._ctypes.create_unicode_buffer

        fake_cert_data = ''
        fake_cert_data += x509constants.PEM_HEADER + '\n'
        fake_cert_data += 'fake cert' + '\n'
        fake_cert_data += x509constants.PEM_FOOTER
        mock_get_cert_base64.return_value = 'fake cert'
        mock_CryptStringToBinaryW.return_value = crypttstr
        mock_CertOpenStore.return_value = store_handle
        mock_CertAddEncodedCertificateToStore.return_value = add_enc_cert
        mock_CertGetNameString.side_effect = [2, upn_len]

        expected = [mock.call('fake cert', len('fake cert'),
                              self.x509.cryptoapi.CRYPT_STRING_BASE64, None,
                              mock_byref(), None, None),
                    mock.call('fake cert', len('fake cert'),
                              self.x509.cryptoapi.CRYPT_STRING_BASE64,
                              mock_cast(), mock_byref(), None, None)]
        expected2 = [mock.call(mock_POINTER()(),
                               self.x509.cryptoapi.CERT_NAME_UPN_TYPE,
                               0, None, None, 0),
                     mock.call(mock_POINTER()(),
                               self.x509.cryptoapi.CERT_NAME_UPN_TYPE,
                               0, None, mock_create_unicode_buffer(), 2)]

        if (not crypttstr or store_handle is None or add_enc_cert is None or
                upn_len != 2):
            self.assertRaises(self.x509.cryptoapi.CryptoAPIException,
                              self._x509_manager.import_cert, fake_cert_data,
                              True, self.x509.STORE_NAME_MY)
        else:
            response = self._x509_manager.import_cert(fake_cert_data)

            mock_cast.assert_called_with(mock_malloc(), mock_POINTER())
            self.assertEqual(expected,
                             mock_CryptStringToBinaryW.call_args_list)
            mock_CertOpenStore.assert_called_with(
                self.x509.cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0,
                self.x509.cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE,
                six.text_type(self.x509.STORE_NAME_MY))

            mock_CertAddEncodedCertificateToStore.assert_called_with(
                mock_CertOpenStore(),
                self.x509.cryptoapi.X509_ASN_ENCODING |
                self.x509.cryptoapi.PKCS_7_ASN_ENCODING,
                mock_cast(), mock_DWORD(),
                self.x509.cryptoapi.CERT_STORE_ADD_REPLACE_EXISTING,
                mock_byref())

            mock_create_unicode_buffer.assert_called_with(2)
            self.assertEqual(expected2, mock_CertGetNameString.call_args_list)
            mock_get_cert_thumprint.assert_called_once_with(mock_POINTER()())

            mock_CertFreeCertificateContext.assert_called_once_with(
                mock_POINTER()())
            mock_CertCloseStore.assert_called_once_with(
                mock_CertOpenStore(), 0)

            mock_free.assert_called_once_with(mock_cast())
            self.assertEqual(
                (mock_get_cert_thumprint(),
                 mock_create_unicode_buffer().value), response)

        mock_get_cert_base64.assert_called_with(fake_cert_data)

    def test_import_cert(self):
        self._test_import_cert(crypttstr=True, store_handle='fake handle',
                               add_enc_cert='fake encoded cert', upn_len=2)

    def test_import_cert_CryptStringToBinaryW_fail(self):
        self._test_import_cert(crypttstr=False, store_handle='fake handle',
                               add_enc_cert='fake encoded cert', upn_len=2)

    def test_import_cert_CertOpenStore_fail(self):
        self._test_import_cert(crypttstr=False, store_handle=None,
                               add_enc_cert='fake encoded cert', upn_len=2)

    def test_import_cert_CertAddEncodedCertificateToStore_fail(self):
        self._test_import_cert(crypttstr=True, store_handle='fake handle',
                               add_enc_cert=None, upn_len=2)

    def test_import_cert_CertGetNameString_fail(self):
        self._test_import_cert(crypttstr=True, store_handle='fake handle',
                               add_enc_cert='fake encoded cert', upn_len=3)
