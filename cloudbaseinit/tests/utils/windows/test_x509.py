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
            'sys.modules',
            {'ctypes': self._ctypes,
             'ctypes.windll': mock.MagicMock()})

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
                    mock_HANDLE(), self.x509.cryptoapi.AT_KEYEXCHANGE,
                    0x08000000, mock_byref(mock_HANDLE()))
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
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager.'
                '_get_cert_str')
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
                                      mock_get_cert_str,
                                      mock_malloc, mock_free,
                                      certstr, certificate, enhanced_key,
                                      store_handle, context_to_store):

        mock_POINTER = self._ctypes.POINTER
        mock_byref = self._ctypes.byref
        mock_cast = self._ctypes.cast

        mock_uuid4.return_value = 'fake_name'
        mock_CertCreateSelfSignCertificate.return_value = certificate
        mock_CertAddEnhancedKeyUsageIdentifier.return_value = enhanced_key
        mock_CertStrToName.return_value = certstr
        mock_CertOpenStore.return_value = store_handle
        mock_CertAddCertificateContextToStore.return_value = context_to_store
        if (certstr is None or certificate is None or enhanced_key is None or
                store_handle is None or context_to_store is None):
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

            self.assertEqual((mock_get_cert_thumprint.return_value,
                              mock_get_cert_str.return_value), response)

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

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertAddCertificateContextToStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CertOpenStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertFindCertificateInStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertFreeCertificateContext')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CertCloseStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.PFXImportCertStore')
    @mock.patch('ctypes.pointer')
    @mock.patch('ctypes.POINTER')
    @mock.patch('ctypes.cast')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CRYPTOAPI_BLOB')
    def _test_import_pfx_certificate(self, mock_blob, mock_cast, mock_POINTER,
                                     mock_pointer, mock_import_cert_store,
                                     mock_cert_close_store,
                                     mock_cert_free_context,
                                     mock_find_cert_in_store,
                                     mock_cert_open_store, mock_add_cert_store,
                                     import_store_handle, cert_context_p,
                                     store_handle, machine_keyset=True,
                                     add_cert_to_store=True):

        self.x509.cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE = \
            mock.sentinel.local_machine
        self.x509.cryptoapi.CERT_SYSTEM_STORE_CURRENT_USER = \
            mock.sentinel.current_user
        self.x509.cryptoapi.CERT_STORE_PROV_SYSTEM = \
            mock.sentinel.store_prov_system
        self.x509.cryptoapi.CERT_STORE_ADD_REPLACE_EXISTING = \
            mock.sentinel.cert_add_replace_existing

        if import_store_handle:
            import_store_handle = mock.sentinel.import_store_handle
        if cert_context_p:
            cert_context_p = mock.sentinel.cert_context_p
        if store_handle:
            store_handle = mock.sentinel.store_handle

        mock_blob.return_value = mock.sentinel.pfx_blob
        mock_import_cert_store.return_value = import_store_handle
        mock_find_cert_in_store.return_value = cert_context_p
        mock_cert_open_store.return_value = store_handle
        mock_add_cert_store.return_value = add_cert_to_store

        if (not import_store_handle or not cert_context_p or
                not store_handle or not add_cert_to_store):
            with self.assertRaises(self.x509.cryptoapi.CryptoAPIException):
                self._x509_manager.import_pfx_certificate(
                    str(mock.sentinel.pfx_data), machine_keyset=machine_keyset)
        else:
            self._x509_manager.import_pfx_certificate(
                str(mock.sentinel.pfx_data), machine_keyset=machine_keyset)

        mock_blob.assert_called_once_with()
        mock_cast.assert_called_with(
            str(mock.sentinel.pfx_data), mock_POINTER.return_value)
        mock_import_cert_store.assert_called_with(
            mock_pointer.return_value, None, 0)
        mock_pointer.assert_called_once_with(mock_blob.return_value)
        if import_store_handle:
            if cert_context_p:
                if machine_keyset:
                    flags = mock.sentinel.local_machine
                else:
                    flags = mock.sentinel.current_user
                mock_cert_open_store.assert_called_once_with(
                    mock.sentinel.store_prov_system, 0, 0, flags,
                    six.text_type(self.x509.STORE_NAME_MY))
                if store_handle:
                    mock_add_cert_store.assert_called_once_with(
                        mock_cert_open_store.return_value, cert_context_p,
                        mock.sentinel.cert_add_replace_existing, None)
        call_args = []
        if import_store_handle:
            call_args += [mock.call(import_store_handle, 0)]
        elif store_handle:
            call_args += [mock.call(store_handle, 0)]
        mock_cert_close_store.assert_has_calls(call_args)
        if cert_context_p:
            mock_cert_free_context.assert_called_once_with(cert_context_p)

    def test_import_pfx_certificate_no_import_store_handle(self):
        self._test_import_pfx_certificate(
            import_store_handle=None, cert_context_p=None, store_handle=None)

    def test_import_pfx_certificate_no_cert_context_p(self):
        self._test_import_pfx_certificate(
            import_store_handle=True, cert_context_p=None, store_handle=None)

    def test_import_pfx_certificate_no_store_handle(self):
        self._test_import_pfx_certificate(
            import_store_handle=True, cert_context_p=True, store_handle=None)

    def test_import_pfx_certificate_not_added(self):
        self._test_import_pfx_certificate(
            import_store_handle=True, cert_context_p=True, store_handle=True,
            add_cert_to_store=False)

    def test_import_pfx_certificate(self):
        self._test_import_pfx_certificate(
            import_store_handle=True, cert_context_p=True, store_handle=True,
            machine_keyset=False)

    def test_get_thumbprint_buffer(self):
        mock_result = mock.Mock()
        mock_result.contents = mock.sentinel.contents
        self._ctypes.cast = mock.Mock(return_value=mock_result)
        thumbprint_str = '5c5350ff'
        result = self._x509_manager._get_thumbprint_buffer(
            thumbprint_str)
        self.assertEqual(result, mock_result.contents)

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CertCloseStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertFindCertificateInStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CertOpenStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.CRYPTOAPI_BLOB')
    def _test_find_certificate_in_store(self, mock_blob, mock_OpenStore,
                                        mock_FindCertificateInStore,
                                        mock_CloseStore, machine_keyset=True,
                                        store_handle=True,
                                        cert_context_p=True):
        self._x509_manager._get_thumbprint_buffer = mock.Mock()
        (self._x509_manager._get_thumbprint_buffer.
            return_value) = str(mock.sentinel.thumbprint)
        mock_blob.return_value = mock.Mock()
        mock_OpenStore.return_value = store_handle
        mock_FindCertificateInStore.return_value = cert_context_p
        if not store_handle or not cert_context_p:
            with self.assertRaises(self.x509.cryptoapi.CryptoAPIException):
                self._x509_manager._find_certificate_in_store(
                    mock.sentinel.thumbprint_str, machine_keyset)
        else:
            result = self._x509_manager._find_certificate_in_store(
                mock.sentinel.thumbprint_str, machine_keyset)
            self.assertEqual(result, cert_context_p)

        self._x509_manager._get_thumbprint_buffer.assert_called_once_with(
            mock.sentinel.thumbprint_str)
        mock_blob.assert_called_once_with()
        if store_handle:
            mock_CloseStore.assert_called_once_with(store_handle, 0)

    def test_find_certificate_in_store(self):
        self._test_find_certificate_in_store(machine_keyset=None)

    def test_find_certificate_in_store_no_store_handle(self):
        self._test_find_certificate_in_store(store_handle=False)

    def test_find_certificate_in_store_no_cert_context_p(self):
        self._test_find_certificate_in_store(cert_context_p=False)

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertFreeCertificateContext')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertDeleteCertificateFromStore')
    def _test_delete_certificate_from_store(self, mock_delete_cert,
                                            mock_free_cert,
                                            cert_context_p=True,
                                            delete_cert=True):
        self._x509_manager._find_certificate_in_store = mock.Mock()
        (self._x509_manager._find_certificate_in_store.
            return_value) = cert_context_p
        mock_delete_cert.return_value = delete_cert

        if not cert_context_p or not delete_cert:
            with self.assertRaises(self.x509.cryptoapi.CryptoAPIException):
                self._x509_manager.delete_certificate_from_store(
                    mock.sentinel.thumbprint_str, mock.sentinel.machine_keyset,
                    mock.sentinel.store_name)
        else:
            self._x509_manager.delete_certificate_from_store(
                mock.sentinel.thumbprint_str, mock.sentinel.machine_keyset,
                mock.sentinel.store_name)

        self._x509_manager._find_certificate_in_store.assert_called_once_with(
            mock.sentinel.thumbprint_str, mock.sentinel.machine_keyset,
            mock.sentinel.store_name)
        if not cert_context_p:
            self.assertEqual(mock_delete_cert.call_count, 0)
        else:
            mock_free_cert.assert_called_once_with(cert_context_p)

    def test_delete_certificate_from_store(self):
        self._test_delete_certificate_from_store()

    def test_delete_certificate_from_store_no_cert_context_p(self):
        self._test_delete_certificate_from_store(cert_context_p=False)

    def test_delete_certificate_from_store_delete_cert_failed(self):
        self._test_delete_certificate_from_store(delete_cert=False)

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertFreeCertificateContext')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CRYPT_DECRYPT_MESSAGE_PARA')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertCloseStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertDeleteCertificateFromStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CryptDecryptMessage')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertAddCertificateLinkToStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CertOpenStore')
    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CryptStringToBinaryW')
    def _test_decode_pkcs7_base64_blob(self, mock_StringToBinary,
                                       mock_OpenStore, mock_AddCert,
                                       mock_Decrypt, mock_DeleteCert,
                                       mock_CloseStore, mock_decrypt_para,
                                       mock_FreeCert,
                                       string_to_binary_data=True,
                                       store_handle=True,
                                       string_to_binary_data_value=True,
                                       add_cert=True, decrypt_by_ref=True,
                                       decrypt_by_pointer=True):
        data = str(mock.sentinel.data)
        self._x509_manager._find_certificate_in_store = mock.Mock()
        mock_StringToBinary.side_effect = [
            string_to_binary_data, string_to_binary_data_value]
        mock_OpenStore.return_value = store_handle
        mock_AddCert.return_value = add_cert
        mock_Decrypt.side_effect = [decrypt_by_ref, decrypt_by_pointer]

        if (string_to_binary_data and store_handle and add_cert and
                string_to_binary_data_value and decrypt_by_ref and
                decrypt_by_pointer):
            result = self._x509_manager.decode_pkcs7_base64_blob(
                data, mock.sentinel.thumbprint_str,
                mock.sentinel.machine_keyset, mock.sentinel.store_name)
            self.assertEqual(
                result, bytes(self._ctypes.create_string_buffer.return_value))
        else:
            with self.assertRaises(self.x509.cryptoapi.CryptoAPIException):
                self._x509_manager.decode_pkcs7_base64_blob(
                    data, mock.sentinel.thumbprint_str,
                    mock.sentinel.machine_keyset, mock.sentinel.store_name)

    def test_decode_pkcs7_base64_blob(self):
        self._test_decode_pkcs7_base64_blob()

    def test_decode_pkcs7_base64_blob_encrypt_data_fails(self):
        self._test_decode_pkcs7_base64_blob(string_to_binary_data=False)

    def test_decode_pkcs7_base64_blob_no_store_handle(self):
        self._test_decode_pkcs7_base64_blob(store_handle=False)

    def test_decode_pkcs7_base64_blob_encrypt_data_value_fails(self):
        self._test_decode_pkcs7_base64_blob(string_to_binary_data_value=False)

    def test_decode_pkcs7_base64_blob_add_certificate_fails(self):
        self._test_decode_pkcs7_base64_blob(add_cert=False)

    def test_decode_pkcs7_base64_blob_decrypt_by_ref_fails(self):
        self._test_decode_pkcs7_base64_blob(decrypt_by_ref=False)

    def test_decode_pkcs7_base64_blob_decrypt_by_pointer_fails(self):
        self._test_decode_pkcs7_base64_blob(decrypt_by_pointer=False)

    @mock.patch('cloudbaseinit.utils.windows.cryptoapi.'
                'CryptBinaryToString')
    def _test_get_cert_str(self, mock_CryptBinaryToString, works):
        mock_DWORD = self._ctypes.wintypes.DWORD
        mock_DWORD.return_value = mock.Mock()
        mock_cert_context_p = mock.Mock()
        if not all(works):
            mock_CryptBinaryToString.side_effect = works
            with self.assertRaises(self.x509.cryptoapi.CryptoAPIException):
                self._x509_manager._get_cert_str(mock_cert_context_p)
        else:
            mock_create_unicode_buffer = self._ctypes.create_unicode_buffer
            mock_cer_str = mock.Mock()
            mock_create_unicode_buffer.return_value = mock_cer_str
            result = self._x509_manager._get_cert_str(mock_cert_context_p)
            self.assertEqual(result, mock_cer_str.value)
        mock_DWORD.assert_called_once_with(0)
        calls = [mock.call(mock_cert_context_p.contents.pbCertEncoded,
                           mock_cert_context_p.contents.cbCertEncoded,
                           self.x509.cryptoapi.CRYPT_STRING_BASE64,
                           None, self._ctypes.byref.return_value)]
        if all(works):
            calls += [mock.call(mock_cert_context_p.contents.pbCertEncoded,
                                mock_cert_context_p.contents.cbCertEncoded,
                                self.x509.cryptoapi.CRYPT_STRING_BASE64,
                                mock_create_unicode_buffer.return_value,
                                self._ctypes.byref.return_value)]
        self.assertTrue(calls, mock_CryptBinaryToString.calls)

    def test_get_cert_str_fails(self):
        self._test_get_cert_str(works=[False, False])

    def test_get_cert_str_fails_2(self):
        self._test_get_cert_str(works=[False, True])

    def test_get_cert_str(self):
        self._test_get_cert_str(works=[True, True])
