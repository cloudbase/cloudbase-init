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

import base64
import ctypes
import ctypes.util
import struct
import sys

if sys.platform == "win32":
    openssl_lib_path = "libeay32.dll"
else:
    openssl_lib_path = ctypes.util.find_library("ssl")

openssl = ctypes.CDLL(openssl_lib_path)
clib = ctypes.CDLL(ctypes.util.find_library("c"))


class RSA(ctypes.Structure):
    _fields_ = [
        ("pad", ctypes.c_int),
        ("version", ctypes.c_long),
        ("meth", ctypes.c_void_p),
        ("engine", ctypes.c_void_p),
        ("n", ctypes.c_void_p),
        ("e", ctypes.c_void_p),
        ("d", ctypes.c_void_p),
        ("p", ctypes.c_void_p),
        ("q", ctypes.c_void_p),
        ("dmp1", ctypes.c_void_p),
        ("dmq1", ctypes.c_void_p),
        ("iqmp", ctypes.c_void_p),
        ("sk", ctypes.c_void_p),
        ("dummy", ctypes.c_int),
        ("references", ctypes.c_int),
        ("flags", ctypes.c_int),
        ("_method_mod_n", ctypes.c_void_p),
        ("_method_mod_p", ctypes.c_void_p),
        ("_method_mod_q", ctypes.c_void_p),
        ("bignum_data", ctypes.c_char_p),
        ("blinding", ctypes.c_void_p),
        ("mt_blinding", ctypes.c_void_p)
    ]

openssl.RSA_PKCS1_PADDING = 1

openssl.RSA_new.restype = ctypes.POINTER(RSA)

openssl.BN_bin2bn.restype = ctypes.c_void_p
openssl.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]

openssl.BN_new.restype = ctypes.c_void_p

openssl.RSA_size.restype = ctypes.c_int
openssl.RSA_size.argtypes = [ctypes.POINTER(RSA)]

openssl.RSA_public_encrypt.argtypes = [ctypes.c_int,
                                       ctypes.c_char_p,
                                       ctypes.c_char_p,
                                       ctypes.POINTER(RSA),
                                       ctypes.c_int]
openssl.RSA_public_encrypt.restype = ctypes.c_int

openssl.RSA_free.argtypes = [ctypes.POINTER(RSA)]

openssl.PEM_write_RSAPublicKey.restype = ctypes.c_int
openssl.PEM_write_RSAPublicKey.argtypes = [ctypes.c_void_p,
                                           ctypes.POINTER(RSA)]

openssl.ERR_get_error.restype = ctypes.c_long
openssl.ERR_get_error.argtypes = []

openssl.ERR_error_string_n.restype = ctypes.c_void_p
openssl.ERR_error_string_n.argtypes = [ctypes.c_long,
                                       ctypes.c_char_p,
                                       ctypes.c_int]

openssl.ERR_load_crypto_strings.restype = ctypes.c_int
openssl.ERR_load_crypto_strings.argtypes = []

clib.fopen.restype = ctypes.c_void_p
clib.fopen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

clib.fclose.restype = ctypes.c_int
clib.fclose.argtypes = [ctypes.c_void_p]


class CryptException(Exception):
    pass


class OpenSSLException(CryptException):

    def __init__(self):
        message = self._get_openssl_error_msg()
        super(OpenSSLException, self).__init__(message)

    def _get_openssl_error_msg(self):
        openssl.ERR_load_crypto_strings()
        errno = openssl.ERR_get_error()
        errbuf = ctypes.create_string_buffer(1024)
        openssl.ERR_error_string_n(errno, errbuf, 1024)
        return errbuf.value.decode("ascii")


class RSAWrapper(object):

    def __init__(self, rsa_p):
        self._rsa_p = rsa_p

    def __enter__(self):
        return self

    def __exit__(self, tp, value, tb):
        self.free()

    def free(self):
        openssl.RSA_free(self._rsa_p)

    def public_encrypt(self, clear_text):
        flen = len(clear_text)
        rsa_size = openssl.RSA_size(self._rsa_p)
        enc_text = ctypes.create_string_buffer(rsa_size)

        enc_text_len = openssl.RSA_public_encrypt(flen,
                                                  clear_text,
                                                  enc_text,
                                                  self._rsa_p,
                                                  openssl.RSA_PKCS1_PADDING)
        if enc_text_len == -1:
            raise OpenSSLException()

        return enc_text[:enc_text_len]


class CryptManager(object):

    def load_ssh_rsa_public_key(self, ssh_pub_key):
        ssh_rsa_prefix = "ssh-rsa "

        if not ssh_pub_key.startswith(ssh_rsa_prefix):
            raise CryptException('Invalid SSH key')

        s = ssh_pub_key[len(ssh_rsa_prefix):]
        idx = s.find(' ')
        if idx >= 0:
            b64_pub_key = s[:idx]
        else:
            b64_pub_key = s

        pub_key = base64.b64decode(b64_pub_key)

        offset = 0

        key_type_len = struct.unpack('>I', pub_key[offset:offset + 4])[0]
        offset += 4

        key_type = pub_key[offset:offset + key_type_len].decode('utf-8')
        offset += key_type_len

        if key_type not in ['ssh-rsa', 'rsa', 'rsa1']:
            raise CryptException('Unsupported SSH key type "%s". '
                                 'Only RSA keys are currently supported'
                                 % key_type)

        rsa_p = openssl.RSA_new()
        try:
            rsa_p.contents.e = openssl.BN_new()
            rsa_p.contents.n = openssl.BN_new()

            e_len = struct.unpack('>I', pub_key[offset:offset + 4])[0]
            offset += 4

            e_key_bin = pub_key[offset:offset + e_len]
            offset += e_len

            if not openssl.BN_bin2bn(e_key_bin, e_len, rsa_p.contents.e):
                raise OpenSSLException()

            n_len = struct.unpack('>I', pub_key[offset:offset + 4])[0]
            offset += 4

            n_key_bin = pub_key[offset:offset + n_len]
            offset += n_len

            if offset != len(pub_key):
                raise CryptException('Invalid SSH key')

            if not openssl.BN_bin2bn(n_key_bin, n_len, rsa_p.contents.n):
                raise OpenSSLException()

            return RSAWrapper(rsa_p)
        except Exception:
            openssl.RSA_free(rsa_p)
            raise
