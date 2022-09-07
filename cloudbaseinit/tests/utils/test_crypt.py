# Copyright 2016 Cloudbase Solutions Srl
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

import unittest

from cloudbaseinit.utils import crypt


class TestOpenSSLException(unittest.TestCase):

    def setUp(self):
        self._openssl = crypt.OpenSSLException()

    def test_get_openssl_error_msg(self):
        expected_err_msg = u'error:00000000:lib(0):func(0):reason(0)'
        expected_err_msg_py10 = u'error:00000000:lib(0)::reason(0)'
        err_msg = self._openssl._get_openssl_error_msg()
        self.assertIn(err_msg, [expected_err_msg, expected_err_msg_py10])


class TestCryptManager(unittest.TestCase):

    def setUp(self):
        self._crypt_manager = crypt.CryptManager()

    def test_load_ssh_rsa_public_key_invalid(self):
        ssh_pub_key = "ssh"
        exc = Exception
        self.assertRaises(exc, self._crypt_manager.load_ssh_rsa_public_key,
                          ssh_pub_key)
