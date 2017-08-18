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

from ctypes import windll
from ctypes import wintypes


class CryptoAPIException(Exception):

    def __init__(self):
        message = self._get_windows_error()
        super(CryptoAPIException, self).__init__(message)

    def _get_windows_error(self):
        err_code = GetLastError()
        return "CryptoAPI error: 0x%0x" % err_code


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ('wYear', wintypes.WORD),
        ('wMonth', wintypes.WORD),
        ('wDayOfWeek', wintypes.WORD),
        ('wDay', wintypes.WORD),
        ('wHour', wintypes.WORD),
        ('wMinute', wintypes.WORD),
        ('wSecond', wintypes.WORD),
        ('wMilliseconds', wintypes.WORD),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [
        ('dwLowDateTime', wintypes.DWORD),
        ('dwHighDateTime', wintypes.DWORD),
    ]


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('dwCertEncodingType', wintypes.DWORD),
        ('pbCertEncoded', ctypes.POINTER(wintypes.BYTE)),
        ('cbCertEncoded', wintypes.DWORD),
        ('pCertInfo', ctypes.c_void_p),
        ('hCertStore', wintypes.HANDLE),
    ]


class CRYPTOAPI_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(wintypes.BYTE)),
    ]


class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [
        ('pszObjId', wintypes.LPSTR),
        ('Parameters', CRYPTOAPI_BLOB),
    ]


class CRYPT_KEY_PROV_PARAM(ctypes.Structure):
    _fields_ = [
        ('dwParam', wintypes.DWORD),
        ('pbData', ctypes.POINTER(wintypes.BYTE)),
        ('cbData', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
    ]


class CRYPT_KEY_PROV_INFO(ctypes.Structure):
    _fields_ = [
        ('pwszContainerName', wintypes.LPWSTR),
        ('pwszProvName', wintypes.LPWSTR),
        ('dwProvType', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('cProvParam', wintypes.DWORD),
        ('cProvParam', ctypes.POINTER(CRYPT_KEY_PROV_PARAM)),
        ('dwKeySpec', wintypes.DWORD),
    ]


class CRYPT_DECRYPT_MESSAGE_PARA(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('dwMsgAndCertEncodingType', wintypes.DWORD),
        ('cCertStore', wintypes.DWORD),
        ('rghCertStore', ctypes.POINTER(wintypes.HANDLE)),
        ('dwFlags', wintypes.DWORD),
    ]


class CERT_KEY_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('hNCryptKey', wintypes.HANDLE),
        ('dwKeySpec', wintypes.DWORD),
    ]


AT_KEYEXCHANGE = 1
AT_SIGNATURE = 2
CERT_NAME_UPN_TYPE = 8
CERT_SHA1_HASH_PROP_ID = 3
CERT_STORE_ADD_REPLACE_EXISTING = 3
CERT_STORE_PROV_MEMORY = wintypes.LPSTR(2)
CERT_STORE_PROV_SYSTEM = wintypes.LPSTR(10)
CERT_SYSTEM_STORE_CURRENT_USER = 0x10000
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x20000
CERT_X500_NAME_STR = 3
CERT_STORE_ADD_NEW = 1
CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
CERT_STORE_CREATE_NEW_FLAG = 0x2000
CRYPT_SILENT = 64
CRYPT_MACHINE_KEYSET = 32
CRYPT_NEWKEYSET = 8
CRYPT_STRING_BASE64 = 1
PKCS_7_ASN_ENCODING = 0x10000
PROV_RSA_FULL = 1
X509_ASN_ENCODING = 1
CERT_FIND_ANY = 0
CERT_FIND_SHA1_HASH = 0x10000
CERT_KEY_PROV_INFO_PROP_ID = 2
CERT_KEY_CONTEXT_PROP_ID = 5

szOID_PKIX_KP_SERVER_AUTH = b"1.3.6.1.5.5.7.3.1"
szOID_RSA_SHA1RSA = b"1.2.840.113549.1.1.5"

advapi32 = windll.advapi32
crypt32 = windll.crypt32
kernel32 = windll.kernel32

advapi32.CryptAcquireContextW.restype = wintypes.BOOL
advapi32.CryptAcquireContextW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                          wintypes.LPCWSTR, wintypes.DWORD,
                                          wintypes.DWORD]
CryptAcquireContext = advapi32.CryptAcquireContextW

advapi32.CryptReleaseContext.restype = wintypes.BOOL
advapi32.CryptReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
CryptReleaseContext = advapi32.CryptReleaseContext

advapi32.CryptGenKey.restype = wintypes.BOOL
advapi32.CryptGenKey.argtypes = [wintypes.HANDLE,
                                 wintypes.DWORD,
                                 wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
CryptGenKey = advapi32.CryptGenKey

advapi32.CryptDestroyKey.restype = wintypes.BOOL
advapi32.CryptDestroyKey.argtypes = [wintypes.HANDLE]
CryptDestroyKey = advapi32.CryptDestroyKey

crypt32.CertStrToNameW.restype = wintypes.BOOL
crypt32.CertStrToNameW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR,
                                   wintypes.DWORD, ctypes.c_void_p,
                                   ctypes.POINTER(wintypes.BYTE),
                                   ctypes.POINTER(wintypes.DWORD),
                                   ctypes.POINTER(wintypes.LPCWSTR)]
CertStrToName = crypt32.CertStrToNameW

# TODO(alexpilotti): the following time related functions are not CryptoAPI
# specific, putting them in a separate module would be more correct
kernel32.GetSystemTime.restype = None
kernel32.GetSystemTime.argtypes = [ctypes.POINTER(SYSTEMTIME)]
GetSystemTime = kernel32.GetSystemTime

kernel32.SystemTimeToFileTime.restype = wintypes.BOOL
kernel32.SystemTimeToFileTime.argtypes = [ctypes.POINTER(SYSTEMTIME),
                                          ctypes.POINTER(FILETIME)]
SystemTimeToFileTime = kernel32.SystemTimeToFileTime

kernel32.FileTimeToSystemTime.restype = wintypes.BOOL
kernel32.FileTimeToSystemTime.argtypes = [ctypes.POINTER(FILETIME),
                                          ctypes.POINTER(SYSTEMTIME)]
FileTimeToSystemTime = kernel32.FileTimeToSystemTime

# TODO(alexpilotti): this is not a CryptoAPI function, putting it in a separate
# module would be more correct
kernel32.GetLastError.restype = wintypes.DWORD
kernel32.GetLastError.argtypes = []
GetLastError = kernel32.GetLastError

crypt32.CertCreateSelfSignCertificate.restype = ctypes.POINTER(CERT_CONTEXT)
crypt32.CertCreateSelfSignCertificate.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CRYPTOAPI_BLOB),
    wintypes.DWORD,
    ctypes.POINTER(CRYPT_KEY_PROV_INFO),
    ctypes.POINTER(CRYPT_ALGORITHM_IDENTIFIER),
    ctypes.POINTER(SYSTEMTIME),
    ctypes.POINTER(SYSTEMTIME),
    # PCERT_EXTENSIONS
    ctypes.c_void_p]
CertCreateSelfSignCertificate = crypt32.CertCreateSelfSignCertificate

crypt32.CertAddEnhancedKeyUsageIdentifier.restype = wintypes.BOOL
crypt32.CertAddEnhancedKeyUsageIdentifier.argtypes = [
    ctypes.POINTER(CERT_CONTEXT),
    wintypes.LPCSTR]
CertAddEnhancedKeyUsageIdentifier = crypt32.CertAddEnhancedKeyUsageIdentifier

crypt32.CertOpenStore.restype = wintypes.HANDLE
crypt32.CertOpenStore.argtypes = [wintypes.LPCSTR, wintypes.DWORD,
                                  wintypes.HANDLE, wintypes.DWORD,
                                  ctypes.c_void_p]
CertOpenStore = crypt32.CertOpenStore

crypt32.CertAddCertificateContextToStore.restype = wintypes.BOOL
crypt32.CertAddCertificateContextToStore.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CERT_CONTEXT),
    wintypes.DWORD,
    ctypes.POINTER(CERT_CONTEXT)]
CertAddCertificateContextToStore = crypt32.CertAddCertificateContextToStore

crypt32.CryptStringToBinaryW.restype = wintypes.BOOL
crypt32.CryptStringToBinaryW.argtypes = [wintypes.LPCWSTR,
                                         wintypes.DWORD,
                                         wintypes.DWORD,
                                         ctypes.POINTER(wintypes.BYTE),
                                         ctypes.POINTER(wintypes.DWORD),
                                         ctypes.POINTER(wintypes.DWORD),
                                         ctypes.POINTER(wintypes.DWORD)]
CryptStringToBinaryW = crypt32.CryptStringToBinaryW

crypt32.CertAddEncodedCertificateToStore.restype = wintypes.BOOL
crypt32.CertAddEncodedCertificateToStore.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.BYTE),
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.POINTER(CERT_CONTEXT))]
CertAddEncodedCertificateToStore = crypt32.CertAddEncodedCertificateToStore

crypt32.CertGetNameStringW.restype = wintypes.DWORD
crypt32.CertGetNameStringW.argtypes = [ctypes.POINTER(CERT_CONTEXT),
                                       wintypes.DWORD,
                                       wintypes.DWORD,
                                       ctypes.c_void_p,
                                       wintypes.LPWSTR,
                                       wintypes.DWORD]
CertGetNameString = crypt32.CertGetNameStringW

crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
crypt32.CertFreeCertificateContext.argtypes = [ctypes.POINTER(CERT_CONTEXT)]
CertFreeCertificateContext = crypt32.CertFreeCertificateContext

crypt32.CertCloseStore.restype = wintypes.BOOL
crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
CertCloseStore = crypt32.CertCloseStore

crypt32.CertGetCertificateContextProperty.restype = wintypes.BOOL
crypt32.CertGetCertificateContextProperty.argtypes = [
    ctypes.POINTER(CERT_CONTEXT),
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD)]
CertGetCertificateContextProperty = crypt32.CertGetCertificateContextProperty

crypt32.CryptBinaryToStringW.restype = wintypes.BOOL
crypt32.CryptBinaryToStringW.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD)]
CryptBinaryToString = crypt32.CryptBinaryToStringW

crypt32.CryptDecryptMessage.restype = wintypes.BOOL
crypt32.CryptDecryptMessage.argtypes = [
    ctypes.POINTER(CRYPT_DECRYPT_MESSAGE_PARA),
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p]
CryptDecryptMessage = crypt32.CryptDecryptMessage

crypt32.CertAddCertificateLinkToStore.restype = wintypes.BOOL
crypt32.CertAddCertificateLinkToStore.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CERT_CONTEXT),
    wintypes.DWORD,
    ctypes.c_void_p
]
CertAddCertificateLinkToStore = crypt32.CertAddCertificateLinkToStore

crypt32.CertFindCertificateInStore.restype = ctypes.POINTER(CERT_CONTEXT)
crypt32.CertFindCertificateInStore.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p]
CertFindCertificateInStore = crypt32.CertFindCertificateInStore

crypt32.CertSetCertificateContextProperty.restype = wintypes.BOOL
crypt32.CertSetCertificateContextProperty.argtypes = [
    ctypes.POINTER(CERT_CONTEXT),
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p]
CertSetCertificateContextProperty = crypt32.CertSetCertificateContextProperty

crypt32.PFXImportCertStore.restype = wintypes.HANDLE
crypt32.PFXImportCertStore.argtypes = [
    ctypes.POINTER(CRYPTOAPI_BLOB),
    wintypes.LPCWSTR,
    wintypes.DWORD]
PFXImportCertStore = crypt32.PFXImportCertStore

crypt32.CertDeleteCertificateFromStore.restype = wintypes.BOOL
crypt32.CertDeleteCertificateFromStore.argtypes = [
    ctypes.POINTER(CERT_CONTEXT)]
CertDeleteCertificateFromStore = crypt32.CertDeleteCertificateFromStore
