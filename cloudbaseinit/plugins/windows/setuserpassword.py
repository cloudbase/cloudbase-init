# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions Srl
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

from cloudbaseinit.metadata.services import base as services_base
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base
from cloudbaseinit.utils import crypt

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class SetUserPasswordPlugin(base.BasePlugin):
    _post_password_md_ver = '2013-04-04'
    _max_password_set_retry_count = 10

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

    def _get_password(self, osutils):
        LOG.debug('Generating a random user password')
        # Generate a random password
        # Limit to 14 chars for compatibility with NT
        return osutils.generate_random_password(14)

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

    def _set_password(self, osutils, user_name):
        i = 0
        while True:
            try:
                # The retry is due to Windows not accepting some of
                # the randomly generated passwords due to complexity
                # constraints
                password = self._get_password(osutils)
                LOG.info('Setting the user\'s password')
                osutils.set_user_password(user_name, password)
                return password
            except:
                if i < self._max_password_set_retry_count:
                    i += 1
                else:
                    raise

    def execute(self, service):
        user_name = CONF.username

        if not service.can_post_password:
            LOG.info('Cannot set the password in the metadata as it is '
                     'not supported by this service')
            return (base.PLUGIN_EXECUTION_DONE, False)

        if service.is_password_set(self._post_password_md_ver):
            LOG.debug('User\'s password already set in the instance metadata')
        else:
            osutils = osutils_factory.OSUtilsFactory().get_os_utils()
            if osutils.user_exists(user_name):
                password = self._set_password(osutils, user_name)
                self._set_metadata_password(password, service)

        return (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)
