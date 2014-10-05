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

import base64

from oslo.config import cfg

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base
from cloudbaseinit.plugins import constants
from cloudbaseinit.utils import crypt

opts = [
    cfg.BoolOpt('inject_user_password', default=True, help='Set the password '
                'provided in the configuration. If False or no password is '
                'provided, a random one will be set'),
]

CONF = cfg.CONF
CONF.register_opts(opts)
CONF.import_opt('username', 'cloudbaseinit.plugins.windows.createuser')

LOG = logging.getLogger(__name__)


class SetUserPasswordPlugin(base.BasePlugin):
    def _encrypt_password(self, ssh_pub_key, password):
        cm = crypt.CryptManager()
        with cm.load_ssh_rsa_public_key(ssh_pub_key) as rsa:
            enc_password = rsa.public_encrypt(password)
        return base64.b64encode(enc_password)

    def _get_ssh_public_key(self, service):
        public_keys = service.get_public_keys()
        if public_keys:
            return public_keys[0]

    def _get_password(self, service, osutils):
        if CONF.inject_user_password:
            password = service.get_admin_password()
        else:
            password = None

        if password:
            LOG.warn('Using admin_pass metadata user password. Consider '
                     'changing it as soon as possible')
        else:
            # TODO(alexpilotti): setting a random password can be skipped
            # if it's already present in the shared_data, as it has already
            # been set by the CreateUserPlugin
            LOG.debug('Generating a random user password')
            # Generate a random password
            # Limit to 14 chars for compatibility with NT
            password = osutils.generate_random_password(14)

        return password

    def _set_metadata_password(self, password, service):
        ssh_pub_key = self._get_ssh_public_key(service)
        if ssh_pub_key:
            enc_password_b64 = self._encrypt_password(ssh_pub_key,
                                                      password)
            return service.post_password(enc_password_b64)
        else:
            LOG.info('No SSH public key available for password encryption')
            return True

    def _set_password(self, service, osutils, user_name):
        password = self._get_password(service, osutils)
        LOG.info('Setting the user\'s password')
        osutils.set_user_password(user_name, password)
        return password

    def execute(self, service, shared_data):
        # TODO(alexpilotti): The username selection logic must be set in the
        # CreateUserPlugin instead if using CONF.username
        user_name = shared_data.get(constants.SHARED_DATA_USERNAME,
                                    CONF.username)

        if service.can_post_password and service.is_password_set:
            LOG.debug('User\'s password already set in the instance metadata')
        else:
            osutils = osutils_factory.get_os_utils()
            if osutils.user_exists(user_name):
                password = self._set_password(service, osutils, user_name)
                # TODO(alexpilotti): encrypt with DPAPI
                shared_data[constants.SHARED_DATA_PASSWORD] = password

                if not service.can_post_password:
                    LOG.info('Cannot set the password in the metadata as it '
                             'is not supported by this service')
                    return (base.PLUGIN_EXECUTION_DONE, False)
                else:
                    self._set_metadata_password(password, service)

        return (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)
