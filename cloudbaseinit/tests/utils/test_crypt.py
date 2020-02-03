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

PUB_KEY = '''
AAAAB3NzaC1yc2EAAAADAQABAAABAQDP1e9IAYXwwUKuFtoReGXidwnM1RuXWB53IO0Hg
mbZArXvEIOfgm/l6IsOJwF7znOBn0hClW7ZONPweX1Al9Hy/LInX1x96Aamq4yyKQCmHDiuZc7Qwu
xr82Ph8XfWic/wo4es/ODSYeFT5NoFDhsYII8O9EGoubpQdakxt9skX0X+zg8TYPuIOANGhlaN8nn
U7gYbO7Gt9vZDmYeRACthNzCIg+w38oxmcgmQqQHxPEp4tUtuFfpjptyVvHz273QvisbdymD3RO0L
9oGMdKzjGgcdE1VuhXuucnUWlZuKe7BirxF8glF5NHKzWto67lDRzVI/F1snkTAorm5EWkA9 test
'''


class TestCryptManager(unittest.TestCase):

    def setUp(self):
        self._crypt_manager = crypt.CryptManager()

    def test_load_ssh_rsa_public_key_invalid(self):
        ssh_pub_key = "ssh"
        exc = crypt.CryptException
        self.assertRaises(exc, self._crypt_manager.public_encrypt,
                          ssh_pub_key, '')

    def test_encrypt_password(self):
        ssh_pub_key = "ssh-rsa " + PUB_KEY.replace('\n', "")
        password = 'testpassword'

        response = self._crypt_manager.public_encrypt(
            ssh_pub_key, password)

        self.assertTrue(len(response) > 0)
        self.assertTrue(isinstance(response, bytes))
