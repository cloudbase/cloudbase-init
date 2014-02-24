# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import mock
import sys
import unittest

from oslo.config import cfg

from cloudbaseinit.utils import x509constants
if sys.platform == 'win32':
    from cloudbaseinit.utils.windows import cryptoapi
    from cloudbaseinit.utils.windows import x509

CONF = cfg.CONF


@unittest.skipUnless(sys.platform == "win32", "requires Windows")
class CryptoAPICertManagerTests(unittest.TestCase):

    def setUp(self):
        self._x509 = x509.CryptoAPICertManager()

    @mock.patch('cloudbaseinit.utils.windows.x509.free')
    @mock.patch('ctypes.c_ubyte')
    @mock.patch('ctypes.POINTER')
    @mock.patch('ctypes.cast')
    @mock.patch('cloudbaseinit.utils.windows.x509.malloc')
    @mock.patch('ctypes.byref')
    @mock.patch('ctypes.wintypes.DWORD')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertGetCertificateContextProperty')
    def _test_get_cert_thumprint(self, mock_CertGetCertificateContextProperty,
                                 mock_DWORD, mock_byref, mock_malloc,
                                 mock_cast, mock_POINTER, mock_c_ubyte,
                                 mock_free, ret_val):

        mock_pointer = mock.MagicMock()
        fake_cert_context_p = 'fake context'
        mock_DWORD().value = 10
        mock_CertGetCertificateContextProperty.return_value = ret_val
        mock_POINTER.return_value = mock_pointer
        mock_cast().contents = [16]
        if not ret_val:
            self.assertRaises(cryptoapi.CryptoAPIException,
                              self._x509._get_cert_thumprint,
                              fake_cert_context_p)
        else:
            expected = [mock.call(fake_cert_context_p,
                                  cryptoapi.CERT_SHA1_HASH_PROP_ID,
                                  None, mock_byref()),
                        mock.call(fake_cert_context_p,
                                  cryptoapi.CERT_SHA1_HASH_PROP_ID,
                                  mock_malloc(), mock_byref())]
            response = self._x509._get_cert_thumprint(fake_cert_context_p)
            self.assertEqual(
                mock_CertGetCertificateContextProperty.call_args_list,
                expected)
            mock_malloc.assert_called_with(mock_DWORD())
            mock_cast.assert_called_with(mock_malloc(), mock_pointer)
            mock_free.assert_called_with(mock_malloc())
            self.assertEqual(response, '10')

    def test_get_cert_thumprint(self):
        self._test_get_cert_thumprint(ret_val=True)

    def test_get_cert_thumprint_GetCertificateContextProperty_exception(self):
        self._test_get_cert_thumprint(ret_val=False)

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptDestroyKey')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptReleaseContext')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptGenKey')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CryptAcquireContext')
    @mock.patch('ctypes.byref')
    @mock.patch('ctypes.wintypes.HANDLE')
    def _test_generate_key(self, mock_HANDLE, mock_byref,
                           mock_CryptAcquireContext, mock_CryptGenKey,
                           mock_CryptReleaseContext, mock_CryptDestroyKey,
                           acquired_context, generate_key_ret_val):
        mock_CryptAcquireContext.return_value = acquired_context
        mock_CryptGenKey.return_value = generate_key_ret_val
        if not acquired_context:
            self.assertRaises(cryptoapi.CryptoAPIException,
                              self._x509._generate_key,
                              'fake container', True)
        else:
            if generate_key_ret_val is None:
                self.assertRaises(cryptoapi.CryptoAPIException,
                                  self._x509._generate_key, 'fake container',
                                  True)
                mock_byref.assert_called_with(mock_HANDLE())
            else:
                self._x509._generate_key('fake container', True)
                mock_CryptAcquireContext.assert_called_with(
                    mock_byref(), 'fake container', None,
                    cryptoapi.PROV_RSA_FULL, cryptoapi.CRYPT_MACHINE_KEYSET)
                mock_CryptGenKey.assert_called_with(mock_HANDLE(),
                                                    cryptoapi.AT_SIGNATURE,
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
    @mock.patch('copy.copy')
    @mock.patch('ctypes.byref')
    @mock.patch('cloudbaseinit.utils.windows.x509.malloc')
    @mock.patch('ctypes.POINTER')
    @mock.patch('ctypes.cast')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._generate_key')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._get_cert_thumprint')
    @mock.patch('uuid.uuid4')
    @mock.patch('ctypes.wintypes.DWORD')
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
                                      mock_CertStrToName, mock_DWORD,
                                      mock_uuid4, mock_get_cert_thumprint,
                                      mock_generate_key, mock_cast,
                                      mock_POINTER, mock_malloc, mock_byref,
                                      mock_copy, mock_free, certstr,
                                      certificate, enhanced_key,
                                      store_handle, context_to_store):

        mock_uuid4.return_value = 'fake_name'
        mock_CertCreateSelfSignCertificate.return_value = certificate
        mock_CertAddEnhancedKeyUsageIdentifier.return_value = enhanced_key
        mock_CertStrToName.return_value = certstr
        mock_CertOpenStore.return_value = store_handle
        mock_CertAddCertificateContextToStore.return_value = context_to_store
        if (certstr is None or certificate is None or enhanced_key is None
                or store_handle is None or context_to_store is None):
            self.assertRaises(cryptoapi.CryptoAPIException,
                              self._x509.create_self_signed_cert,
                              'fake subject', 10, True, x509.STORE_NAME_MY)
        else:
            response = self._x509.create_self_signed_cert(
                subject='fake subject')
            mock_cast.assert_called_with(mock_malloc(), mock_POINTER())
            mock_CRYPTOAPI_BLOB.assert_called_once_with()
            mock_CRYPT_KEY_PROV_INFO.assert_called_once_with()
            mock_CRYPT_ALGORITHM_IDENTIFIER.assert_called_once_with()
            mock_SYSTEMTIME.assert_called_once_with()
            mock_GetSystemTime.assert_called_once_with(mock_byref())
            mock_copy.assert_called_once_with(mock_SYSTEMTIME())
            mock_CertCreateSelfSignCertificate.assert_called_once_with(
                None, mock_byref(), 0, mock_byref(),
                mock_byref(), mock_byref(), mock_byref(), None)
            mock_CertAddEnhancedKeyUsageIdentifier.assert_called_with(
                mock_CertCreateSelfSignCertificate(),
                cryptoapi.szOID_PKIX_KP_SERVER_AUTH)
            mock_CertOpenStore.assert_called_with(
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0,
                cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE,
                unicode(x509.STORE_NAME_MY))
            mock_get_cert_thumprint.assert_called_once_with(
                mock_CertCreateSelfSignCertificate())

            mock_CertCloseStore.assert_called_once_with(store_handle, 0)
            mock_CertFreeCertificateContext.assert_called_once_with(
                mock_CertCreateSelfSignCertificate())
            mock_free.assert_called_once_with(mock_cast())

            self.assertEqual(response, mock_get_cert_thumprint())

        mock_generate_key.assert_called_once_with('fake_name', True)

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
        response = self._x509._get_cert_base64(fake_cert_data)
        self.assertEqual(response, 'fake cert')

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
                'CryptStringToBinaryA')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager'
                '._get_cert_base64')
    @mock.patch('ctypes.POINTER')
    @mock.patch('cloudbaseinit.utils.windows.x509.malloc')
    @mock.patch('ctypes.cast')
    @mock.patch('ctypes.byref')
    @mock.patch('ctypes.wintypes.DWORD')
    @mock.patch('ctypes.create_unicode_buffer')
    def _test_import_cert(self, mock_create_unicode_buffer, mock_DWORD,
                          mock_byref, mock_cast,
                          mock_malloc, mock_POINTER, mock_get_cert_base64,
                          mock_CryptStringToBinaryA, mock_CertOpenStore,
                          mock_CertAddEncodedCertificateToStore,
                          mock_CertGetNameString,
                          mock_CertFreeCertificateContext,
                          mock_CertCloseStore, mock_get_cert_thumprint,
                          mock_free, crypttstr, store_handle, add_enc_cert,
                          upn_len):
        fake_cert_data = ''
        fake_cert_data += x509constants.PEM_HEADER + '\n'
        fake_cert_data += 'fake cert' + '\n'
        fake_cert_data += x509constants.PEM_FOOTER
        mock_get_cert_base64.return_value = 'fake cert'
        mock_CryptStringToBinaryA.return_value = crypttstr
        mock_CertOpenStore.return_value = store_handle
        mock_CertAddEncodedCertificateToStore.return_value = add_enc_cert
        mock_CertGetNameString.side_effect = [2, upn_len]

        expected = [mock.call('fake cert', len('fake cert'),
                              cryptoapi.CRYPT_STRING_BASE64, None,
                              mock_byref(), None, None),
                    mock.call('fake cert', len('fake cert'),
                              cryptoapi.CRYPT_STRING_BASE64, mock_cast(),
                              mock_byref(), None, None)]
        expected2 = [mock.call(mock_POINTER()(), cryptoapi.CERT_NAME_UPN_TYPE,
                               0, None, None, 0),
                     mock.call(mock_POINTER()(), cryptoapi.CERT_NAME_UPN_TYPE,
                               0, None, mock_create_unicode_buffer(), 2)]

        if (not crypttstr or store_handle is None or add_enc_cert is None or
                upn_len != 2):
            self.assertRaises(cryptoapi.CryptoAPIException,
                              self._x509.import_cert, fake_cert_data, True,
                              x509.STORE_NAME_MY)
        else:
            response = self._x509.import_cert(fake_cert_data)
            mock_cast.assert_called_with(mock_malloc(), mock_POINTER())
            self.assertEqual(mock_CryptStringToBinaryA.call_args_list,
                             expected)
            mock_CertOpenStore.assert_called_with(
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0,
                cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE,
                unicode(x509.STORE_NAME_MY))
            mock_CertAddEncodedCertificateToStore.assert_called_with(
                mock_CertOpenStore(),
                cryptoapi.X509_ASN_ENCODING | cryptoapi.PKCS_7_ASN_ENCODING,
                mock_cast(), mock_DWORD(),
                cryptoapi.CERT_STORE_ADD_REPLACE_EXISTING, mock_byref())
            mock_create_unicode_buffer.assert_called_with(2)
            self.assertEqual(mock_CertGetNameString.call_args_list, expected2)
            mock_get_cert_thumprint.assert_called_once_with(mock_POINTER()())
            mock_CertFreeCertificateContext.assert_called_once_with(
                mock_POINTER()())
            mock_CertCloseStore.assert_called_once_with(
                mock_CertOpenStore(), 0)
            mock_free.assert_called_once_with(mock_cast())
            self.assertEqual(response, (mock_get_cert_thumprint(),
                                        mock_create_unicode_buffer().value))
        mock_get_cert_base64.assert_called_with(fake_cert_data)

    def test_import_cert(self):
        self._test_import_cert(crypttstr=True, store_handle='fake handle',
                               add_enc_cert='fake encoded cert', upn_len=2)

    def test_import_cert_CryptStringToBinaryA_fail(self):
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
