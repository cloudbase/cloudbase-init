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


import ctypes
from ctypes import wintypes
import uuid

from cloudbaseinit.utils import encoding
from cloudbaseinit.utils.windows import cryptoapi
from cloudbaseinit.utils import x509constants


malloc = ctypes.cdll.msvcrt.malloc
malloc.restype = ctypes.c_void_p
malloc.argtypes = [ctypes.c_size_t]

free = ctypes.cdll.msvcrt.free
free.restype = None
free.argtypes = [ctypes.c_void_p]

STORE_NAME_MY = "My"
STORE_NAME_ROOT = "Root"
STORE_NAME_TRUSTED_PEOPLE = "TrustedPeople"

X509_START_DATE_INTERVAL = -24 * 60 * 60 * 10000000
X509_END_DATE_INTERVAL = 10 * 365 * 24 * 60 * 60 * 10000000


class CryptoAPICertManager(object):
    @staticmethod
    def _get_thumprint_str(thumbprint, size):
        thumbprint_ar = ctypes.cast(
            thumbprint,
            ctypes.POINTER(ctypes.c_ubyte *
                           size)).contents

        thumbprint_str = ""
        for b in thumbprint_ar:
            thumbprint_str += "%02x" % b
        return thumbprint_str

    @staticmethod
    def _get_thumbprint_buffer(thumbprint_str):
        thumbprint_bytes = encoding.hex_to_bytes(thumbprint_str)
        return ctypes.cast(
            ctypes.create_string_buffer(thumbprint_bytes),
            ctypes.POINTER(wintypes.BYTE *
                           len(thumbprint_bytes))).contents

    def _get_cert_thumprint(self, cert_context_p):
        thumbprint = None

        try:
            thumprint_len = wintypes.DWORD()

            if not cryptoapi.CertGetCertificateContextProperty(
                    cert_context_p,
                    cryptoapi.CERT_SHA1_HASH_PROP_ID,
                    None, ctypes.byref(thumprint_len)):
                raise cryptoapi.CryptoAPIException()

            size = ctypes.c_size_t(thumprint_len.value)
            thumbprint = malloc(size)

            if not cryptoapi.CertGetCertificateContextProperty(
                    cert_context_p,
                    cryptoapi.CERT_SHA1_HASH_PROP_ID,
                    thumbprint, ctypes.byref(thumprint_len)):
                raise cryptoapi.CryptoAPIException()

            return self._get_thumprint_str(thumbprint, thumprint_len.value)
        finally:
            if thumbprint:
                free(thumbprint)

    def _generate_key(self, container_name, machine_keyset):
        crypt_prov_handle = wintypes.HANDLE()
        key_handle = wintypes.HANDLE()

        try:
            flags = 0
            if machine_keyset:
                flags |= cryptoapi.CRYPT_MACHINE_KEYSET

            if not cryptoapi.CryptAcquireContext(
                    ctypes.byref(crypt_prov_handle),
                    container_name,
                    None,
                    cryptoapi.PROV_RSA_FULL,
                    flags):
                flags |= cryptoapi.CRYPT_NEWKEYSET
                if not cryptoapi.CryptAcquireContext(
                        ctypes.byref(crypt_prov_handle),
                        container_name,
                        None,
                        cryptoapi.PROV_RSA_FULL,
                        flags):
                    raise cryptoapi.CryptoAPIException()

            # RSA 2048 bits
            if not cryptoapi.CryptGenKey(crypt_prov_handle,
                                         cryptoapi.AT_KEYEXCHANGE,
                                         0x08000000,
                                         ctypes.byref(key_handle)):
                raise cryptoapi.CryptoAPIException()

            return key_handle
        finally:
            if key_handle:
                cryptoapi.CryptDestroyKey(key_handle)
            if crypt_prov_handle:
                cryptoapi.CryptReleaseContext(crypt_prov_handle, 0)

    @staticmethod
    def _add_system_time_interval(system_time, increment):
        '''increment's unit: 10ns'''
        file_time = cryptoapi.FILETIME()
        if not cryptoapi.SystemTimeToFileTime(ctypes.byref(system_time),
                                              ctypes.byref(file_time)):
            raise cryptoapi.CryptoAPIException()

        t = file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)
        t += increment

        file_time.dwLowDateTime = t & 0xFFFFFFFF
        file_time.dwHighDateTime = t >> 32 & 0xFFFFFFFF

        new_system_time = cryptoapi.SYSTEMTIME()
        if not cryptoapi.FileTimeToSystemTime(ctypes.byref(file_time),
                                              ctypes.byref(new_system_time)):
            raise cryptoapi.CryptoAPIException()
        return new_system_time

    def create_self_signed_cert(self, subject, validity_years=10,
                                machine_keyset=True, store_name=STORE_NAME_MY):
        subject_encoded = None
        cert_context_p = None
        store_handle = None

        container_name = str(uuid.uuid4())
        self._generate_key(container_name, machine_keyset)

        try:
            subject_encoded_len = wintypes.DWORD()

            if not cryptoapi.CertStrToName(cryptoapi.X509_ASN_ENCODING,
                                           subject,
                                           cryptoapi.CERT_X500_NAME_STR, None,
                                           None,
                                           ctypes.byref(subject_encoded_len),
                                           None):
                raise cryptoapi.CryptoAPIException()

            size = ctypes.c_size_t(subject_encoded_len.value)
            subject_encoded = ctypes.cast(malloc(size),
                                          ctypes.POINTER(wintypes.BYTE))

            if not cryptoapi.CertStrToName(cryptoapi.X509_ASN_ENCODING,
                                           subject,
                                           cryptoapi.CERT_X500_NAME_STR, None,
                                           subject_encoded,
                                           ctypes.byref(subject_encoded_len),
                                           None):
                raise cryptoapi.CryptoAPIException()

            subject_blob = cryptoapi.CRYPTOAPI_BLOB()
            subject_blob.cbData = subject_encoded_len
            subject_blob.pbData = subject_encoded

            key_prov_info = cryptoapi.CRYPT_KEY_PROV_INFO()
            key_prov_info.pwszContainerName = container_name
            key_prov_info.pwszProvName = None
            key_prov_info.dwProvType = cryptoapi.PROV_RSA_FULL
            key_prov_info.cProvParam = None
            key_prov_info.rgProvParam = None
            key_prov_info.dwKeySpec = cryptoapi.AT_KEYEXCHANGE

            if machine_keyset:
                key_prov_info.dwFlags = cryptoapi.CRYPT_MACHINE_KEYSET
            else:
                key_prov_info.dwFlags = 0

            sign_alg = cryptoapi.CRYPT_ALGORITHM_IDENTIFIER()
            sign_alg.pszObjId = cryptoapi.szOID_RSA_SHA256RSA

            start_time = cryptoapi.SYSTEMTIME()
            cryptoapi.GetSystemTime(ctypes.byref(start_time))

            end_time = self._add_system_time_interval(
                start_time, X509_END_DATE_INTERVAL)

            # Needed in case of time sync issues as PowerShell remoting
            # enforces a valid time interval even for self signed certificates
            start_time = self._add_system_time_interval(
                start_time, X509_START_DATE_INTERVAL)

            cert_context_p = cryptoapi.CertCreateSelfSignCertificate(
                None, ctypes.byref(subject_blob), 0,
                ctypes.byref(key_prov_info),
                ctypes.byref(sign_alg), ctypes.byref(start_time),
                ctypes.byref(end_time), None)
            if not cert_context_p:
                raise cryptoapi.CryptoAPIException()

            if not cryptoapi.CertAddEnhancedKeyUsageIdentifier(
                    cert_context_p, cryptoapi.szOID_PKIX_KP_SERVER_AUTH):
                raise cryptoapi.CryptoAPIException()

            if machine_keyset:
                flags = cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE
            else:
                flags = cryptoapi.CERT_SYSTEM_STORE_CURRENT_USER

            store_handle = cryptoapi.CertOpenStore(
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0, flags, str(store_name))
            if not store_handle:
                raise cryptoapi.CryptoAPIException()

            if not cryptoapi.CertAddCertificateContextToStore(
                    store_handle, cert_context_p,
                    cryptoapi.CERT_STORE_ADD_REPLACE_EXISTING, None):
                raise cryptoapi.CryptoAPIException()

            return (self._get_cert_thumprint(cert_context_p),
                    self._get_cert_str(cert_context_p))

        finally:
            if store_handle:
                cryptoapi.CertCloseStore(store_handle, 0)
            if cert_context_p:
                cryptoapi.CertFreeCertificateContext(cert_context_p)
            if subject_encoded:
                free(subject_encoded)

    def _get_cert_str(self, cert_context_p):
        ch_cer_str = wintypes.DWORD(0)
        if not cryptoapi.CryptBinaryToString(
                cert_context_p.contents.pbCertEncoded,
                cert_context_p.contents.cbCertEncoded,
                cryptoapi.CRYPT_STRING_BASE64,
                None, ctypes.byref(ch_cer_str)):
            raise cryptoapi.CryptoAPIException()

        cer_str = ctypes.create_unicode_buffer(ch_cer_str.value)
        if not cryptoapi.CryptBinaryToString(
                cert_context_p.contents.pbCertEncoded,
                cert_context_p.contents.cbCertEncoded,
                cryptoapi.CRYPT_STRING_BASE64,
                cer_str,
                ctypes.byref(ch_cer_str)):
            raise cryptoapi.CryptoAPIException()

        return cer_str.value

    def _get_cert_base64(self, cert_data):
        """Remove certificate header and footer and also new lines."""
        # It's assured that the certificate is already a string.
        removal = [
            x509constants.PEM_HEADER,
            x509constants.PEM_FOOTER,
            "\r",
            "\n"
        ]
        for remove in removal:
            cert_data = cert_data.replace(remove, "")
        return cert_data

    def _find_certificate_in_store(self, thumbprint_str, machine_keyset=True,
                                   store_name=STORE_NAME_MY):
        store_handle = None

        thumbprint = self._get_thumbprint_buffer(thumbprint_str)
        hash_blob = cryptoapi.CRYPTOAPI_BLOB()
        hash_blob.cbData = len(thumbprint)
        hash_blob.pbData = thumbprint

        try:
            flags = cryptoapi.CERT_STORE_OPEN_EXISTING_FLAG
            if machine_keyset:
                flags |= cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE
            else:
                flags |= cryptoapi.CERT_SYSTEM_STORE_CURRENT_USER

            store_handle = cryptoapi.CertOpenStore(
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0, flags, str(store_name))
            if not store_handle:
                raise cryptoapi.CryptoAPIException()

            cert_context_p = cryptoapi.CertFindCertificateInStore(
                store_handle,
                cryptoapi.X509_ASN_ENCODING | cryptoapi.PKCS_7_ASN_ENCODING,
                0,
                cryptoapi.CERT_FIND_SHA1_HASH,
                ctypes.pointer(hash_blob),
                None)
            if not cert_context_p:
                raise cryptoapi.CryptoAPIException()

            return cert_context_p
        finally:
            if store_handle:
                cryptoapi.CertCloseStore(store_handle, 0)

    def delete_certificate_from_store(self, thumbprint_str,
                                      machine_keyset=True,
                                      store_name=STORE_NAME_MY):
        cert_context_p = None

        try:
            cert_context_p = self._find_certificate_in_store(
                thumbprint_str, machine_keyset, store_name)
            if not cert_context_p:
                raise cryptoapi.CryptoAPIException()

            if not cryptoapi.CertDeleteCertificateFromStore(cert_context_p):
                raise cryptoapi.CryptoAPIException()
        finally:
            if cert_context_p:
                cryptoapi.CertFreeCertificateContext(cert_context_p)

    def import_pfx_certificate(self, pfx_data, pfx_password=None,
                               machine_keyset=True, store_name=STORE_NAME_MY):
        cert_context_p = None
        import_store_handle = None
        store_handle = None

        try:
            pfx_blob = cryptoapi.CRYPTOAPI_BLOB()
            pfx_blob.cbData = len(pfx_data)
            pfx_blob.pbData = ctypes.cast(
                pfx_data, ctypes.POINTER(wintypes.BYTE))

            import_store_handle = cryptoapi.PFXImportCertStore(
                ctypes.pointer(pfx_blob), pfx_password, 0)
            if not import_store_handle:
                raise cryptoapi.CryptoAPIException()

            cert_context_p = cryptoapi.CertFindCertificateInStore(
                import_store_handle,
                cryptoapi.X509_ASN_ENCODING | cryptoapi.PKCS_7_ASN_ENCODING,
                0, cryptoapi.CERT_FIND_ANY, None, None)
            if not cert_context_p:
                raise cryptoapi.CryptoAPIException()

            if machine_keyset:
                flags = cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE
            else:
                flags = cryptoapi.CERT_SYSTEM_STORE_CURRENT_USER

            store_handle = cryptoapi.CertOpenStore(
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0, flags, str(store_name))
            if not store_handle:
                raise cryptoapi.CryptoAPIException()

            if not cryptoapi.CertAddCertificateContextToStore(
                    store_handle, cert_context_p,
                    cryptoapi.CERT_STORE_ADD_REPLACE_EXISTING, None):
                raise cryptoapi.CryptoAPIException()

        finally:
            if import_store_handle:
                cryptoapi.CertCloseStore(import_store_handle, 0)
            if cert_context_p:
                cryptoapi.CertFreeCertificateContext(cert_context_p)
            if store_handle:
                cryptoapi.CertCloseStore(store_handle, 0)

    def decode_pkcs7_base64_blob(self, data, thumbprint_str,
                                 machine_keyset=True,
                                 store_name=STORE_NAME_MY):
        base64_data = data.replace('\r', '').replace('\n', '')
        store_handle = None
        cert_context_p = None

        try:
            data_encoded_len = wintypes.DWORD()

            if not cryptoapi.CryptStringToBinaryW(
                    base64_data, len(base64_data),
                    cryptoapi.CRYPT_STRING_BASE64,
                    None, ctypes.byref(data_encoded_len),
                    None, None):
                raise cryptoapi.CryptoAPIException()

            data_encoded = ctypes.cast(
                ctypes.create_string_buffer(data_encoded_len.value),
                ctypes.POINTER(wintypes.BYTE))

            if not cryptoapi.CryptStringToBinaryW(
                    base64_data, len(base64_data),
                    cryptoapi.CRYPT_STRING_BASE64,
                    data_encoded, ctypes.byref(data_encoded_len),
                    None, None):
                raise cryptoapi.CryptoAPIException()

            store_handle = cryptoapi.CertOpenStore(
                cryptoapi.CERT_STORE_PROV_MEMORY,
                cryptoapi.X509_ASN_ENCODING | cryptoapi.PKCS_7_ASN_ENCODING,
                None, cryptoapi.CERT_STORE_CREATE_NEW_FLAG, None)
            if not store_handle:
                raise cryptoapi.CryptoAPIException()

            cert_context_p = self._find_certificate_in_store(
                thumbprint_str, machine_keyset, store_name)

            if not cryptoapi.CertAddCertificateLinkToStore(
                    store_handle, cert_context_p,
                    cryptoapi.CERT_STORE_ADD_NEW, None):
                raise cryptoapi.CryptoAPIException()

            para = cryptoapi.CRYPT_DECRYPT_MESSAGE_PARA()
            para.cbSize = ctypes.sizeof(cryptoapi.CRYPT_DECRYPT_MESSAGE_PARA)
            para.dwMsgAndCertEncodingType = (cryptoapi.X509_ASN_ENCODING |
                                             cryptoapi.PKCS_7_ASN_ENCODING)
            para.cCertStore = 1
            para.rghCertStore = ctypes.pointer(wintypes.HANDLE(store_handle))
            para.dwFlags = cryptoapi.CRYPT_SILENT

            data_decoded_len = wintypes.DWORD()
            if not cryptoapi.CryptDecryptMessage(
                    ctypes.byref(para),
                    data_encoded,
                    data_encoded_len,
                    None,
                    ctypes.byref(data_decoded_len),
                    None):
                raise cryptoapi.CryptoAPIException()

            data_decoded_buf = ctypes.create_string_buffer(
                data_decoded_len.value)
            data_decoded = ctypes.cast(
                data_decoded_buf, ctypes.POINTER(wintypes.BYTE))

            if not cryptoapi.CryptDecryptMessage(
                    ctypes.pointer(para),
                    data_encoded,
                    data_encoded_len,
                    data_decoded,
                    ctypes.byref(data_decoded_len),
                    None):
                raise cryptoapi.CryptoAPIException()

            return bytes(data_decoded_buf)
        finally:
            if cert_context_p:
                cryptoapi.CertFreeCertificateContext(cert_context_p)
            if store_handle:
                cryptoapi.CertCloseStore(store_handle, 0)

    def import_cert(self, cert_data, machine_keyset=True,
                    store_name=STORE_NAME_MY):

        base64_cert_data = self._get_cert_base64(cert_data)

        cert_encoded = None
        store_handle = None
        cert_context_p = None

        try:
            cert_encoded_len = wintypes.DWORD()

            if not cryptoapi.CryptStringToBinaryW(
                    base64_cert_data, len(base64_cert_data),
                    cryptoapi.CRYPT_STRING_BASE64,
                    None, ctypes.byref(cert_encoded_len),
                    None, None):
                raise cryptoapi.CryptoAPIException()

            size = ctypes.c_size_t(cert_encoded_len.value)
            cert_encoded = ctypes.cast(malloc(size),
                                       ctypes.POINTER(wintypes.BYTE))

            if not cryptoapi.CryptStringToBinaryW(
                    base64_cert_data, len(base64_cert_data),
                    cryptoapi.CRYPT_STRING_BASE64,
                    cert_encoded, ctypes.byref(cert_encoded_len),
                    None, None):
                raise cryptoapi.CryptoAPIException()

            if machine_keyset:
                flags = cryptoapi.CERT_SYSTEM_STORE_LOCAL_MACHINE
            else:
                flags = cryptoapi.CERT_SYSTEM_STORE_CURRENT_USER

            store_handle = cryptoapi.CertOpenStore(
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0, flags, str(store_name))
            if not store_handle:
                raise cryptoapi.CryptoAPIException()

            cert_context_p = ctypes.POINTER(cryptoapi.CERT_CONTEXT)()

            if not cryptoapi.CertAddEncodedCertificateToStore(
                    store_handle,
                    cryptoapi.X509_ASN_ENCODING |
                    cryptoapi.PKCS_7_ASN_ENCODING,
                    cert_encoded, cert_encoded_len,
                    cryptoapi.CERT_STORE_ADD_REPLACE_EXISTING,
                    ctypes.byref(cert_context_p)):
                raise cryptoapi.CryptoAPIException()

            # Get the UPN (1.3.6.1.4.1.311.20.2.3 OID) from the
            # certificate subject alt name
            upn = None
            upn_len = cryptoapi.CertGetNameString(
                cert_context_p,
                cryptoapi.CERT_NAME_UPN_TYPE, 0,
                None, None, 0)
            if upn_len > 1:
                upn_ar = ctypes.create_unicode_buffer(upn_len)
                if cryptoapi.CertGetNameString(
                        cert_context_p,
                        cryptoapi.CERT_NAME_UPN_TYPE,
                        0, None, upn_ar, upn_len) != upn_len:
                    raise cryptoapi.CryptoAPIException()
                upn = upn_ar.value

            thumbprint = self._get_cert_thumprint(cert_context_p)
            return thumbprint, upn
        finally:
            if cert_context_p:
                cryptoapi.CertFreeCertificateContext(cert_context_p)
            if store_handle:
                cryptoapi.CertCloseStore(store_handle, 0)
            if cert_encoded:
                free(cert_encoded)
