# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the 'License'); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import os

from cloudbaseinit.metadata.services import base as services_base
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base
from cloudbaseinit.utils import crypt

opts = [
    cfg.StrOpt('username', default='Admin',
        help='User to be added to the system or updated if already existing'),
    cfg.ListOpt('groups', default=['Administrators'],
        help='List of local groups to which the user specified '
            'in \'username\' will be added'),
    cfg.BoolOpt('inject_user_password', default=True,
        help='Set the password provided in the configuration. '
            'If False or no password is provided, a random one will be set'),
  ]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class CreateUserPlugin(base.BasePlugin):
    _post_password_md_ver = '2013-04-04'

    def _generate_random_password(self, length):
        # On Windows os.urandom() uses CryptGenRandom, which is a
        # cryptographically secure pseudorandom number generator
        b64_password = base64.b64encode(os.urandom(256))
        return b64_password.replace('/', '').replace('+', '')[:length]

    def _encrypt_password(self, ssh_pub_key, password):
        cm = crypt.CryptManager()
        with cm.load_ssh_rsa_public_key(ssh_pub_key) as rsa:
            enc_password = rsa.public_encrypt(password)
        return base64.b64encode(enc_password)

    def _get_ssh_public_key(self, service):
        meta_data = service.get_meta_data('openstack',
                                          self._post_password_md_ver)
        if not 'public_keys' in meta_data:
            return False

        public_keys = meta_data['public_keys']
        ssh_pub_key = None
        for k in public_keys:
            # Get the first key
            ssh_pub_key = public_keys[k]
            break
        return ssh_pub_key

    def _get_password(self, service):
        meta_data = service.get_meta_data('openstack')
        if 'admin_pass' in meta_data and CONF.inject_user_password:
            password = meta_data['admin_pass']
        else:
            # Generate a random password
            # Limit to 14 chars for compatibility with NT
            password = self._generate_random_password(14)
        return password

    def _set_metadata_password(self, password, service):
        try:
            ssh_pub_key = self._get_ssh_public_key(service)
            if ssh_pub_key:
                enc_password_b64 = self._encrypt_password(ssh_pub_key,
                                                          password)
                return service.post_password(enc_password_b64,
                                             self._post_password_md_ver)
            else:
                LOG.info('No SSH public key available for password encryption')
                return True
        except services_base.NotExistingMetadataException:
            # Requested version not available or password feature
            # not implemented
            LOG.info('Cannot set the password in the metadata as it is not '
                     'supported by this metadata version')
            return True

    def execute(self, service):
        user_name = CONF.username

        password = self._get_password(service)

        if service.can_post_password:
            md_pwd_already_set = not self._set_metadata_password(password,
                                                                 service)
        else:
            md_pwd_already_set = False
            LOG.info('Cannot set the password in the metadata as it is not '
                     'supported by this service')

        osutils = osutils_factory.OSUtilsFactory().get_os_utils()
        if not osutils.user_exists(user_name):
            if md_pwd_already_set:
                LOG.warning('Creating user, but the password was not set in '
                            'the metadata as it was previously set')
            osutils.create_user(user_name, password)
            # Create a user profile in order for other plugins
            # to access the user home, etc
            token = osutils.create_user_logon_session(user_name,
                                                      password,
                                                      True)
            osutils.close_user_logon_session(token)
        else:
            if not md_pwd_already_set:
                osutils.set_user_password(user_name, password)
            else:
                LOG.warning('Cannot change the user\'s password as it is '
                            'already set in the metadata')

        for group_name in CONF.groups:
            try:
                osutils.add_user_to_local_group(user_name, group_name)
            except Exception as ex:
                LOG.exception(ex)
                LOG.error('Cannot add user to group "%s"' % group_name)

        return False
