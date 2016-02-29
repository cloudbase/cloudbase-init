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

import six

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

            thumbprint_ar = ctypes.cast(
                thumbprint,
                ctypes.POINTER(ctypes.c_ubyte *
                               thumprint_len.value)).contents

            thumbprint_str = ""
            for b in thumbprint_ar:
                thumbprint_str += "%02x" % b
            return thumbprint_str
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
                                         cryptoapi.AT_SIGNATURE,
                                         0x08000000, key_handle):
                raise cryptoapi.CryptoAPIException()
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
            key_prov_info.dwKeySpec = cryptoapi.AT_SIGNATURE

            if machine_keyset:
                key_prov_info.dwFlags = cryptoapi.CRYPT_MACHINE_KEYSET
            else:
                key_prov_info.dwFlags = 0

            sign_alg = cryptoapi.CRYPT_ALGORITHM_IDENTIFIER()
            sign_alg.pszObjId = cryptoapi.szOID_RSA_SHA1RSA

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
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0, flags,
                six.text_type(store_name))
            if not store_handle:
                raise cryptoapi.CryptoAPIException()

            if not cryptoapi.CertAddCertificateContextToStore(
                    store_handle, cert_context_p,
                    cryptoapi.CERT_STORE_ADD_REPLACE_EXISTING, None):
                raise cryptoapi.CryptoAPIException()

            return self._get_cert_thumprint(cert_context_p)

        finally:
            if store_handle:
                cryptoapi.CertCloseStore(store_handle, 0)
            if cert_context_p:
                cryptoapi.CertFreeCertificateContext(cert_context_p)
            if subject_encoded:
                free(subject_encoded)

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
                cryptoapi.CERT_STORE_PROV_SYSTEM, 0, 0, flags,
                six.text_type(store_name))
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
