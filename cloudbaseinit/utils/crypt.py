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

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


class CryptException(Exception):
    pass


class CryptManager(object):

    def public_encrypt(self, ssh_pub_key, password):
        ssh_rsa_prefix = "ssh-rsa "

        if not ssh_pub_key.startswith(ssh_rsa_prefix):
            raise CryptException('Invalid SSH key')

        rsa_public_key = serialization.load_ssh_public_key(
            ssh_pub_key.encode(), backends.default_backend())
        enc_password = rsa_public_key.encrypt(
            password.encode(),
            padding.PKCS1v15()
        )
        return base64.b64encode(enc_password)
