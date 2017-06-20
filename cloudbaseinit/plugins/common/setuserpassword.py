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

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import constants as plugin_constant
from cloudbaseinit.utils import crypt


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class SetUserPasswordPlugin(base.BasePlugin):

    def _encrypt_password(self, ssh_pub_key, password):
        cm = crypt.CryptManager()
        with cm.load_ssh_rsa_public_key(ssh_pub_key) as rsa:
            enc_password = rsa.public_encrypt(password.encode())
        return base64.b64encode(enc_password)

    def _get_password(self, service, shared_data):
        injected = False
        if CONF.inject_user_password:
            password = service.get_admin_password()
        else:
            password = None

        if password:
            injected = True
            LOG.warn('Using admin_pass metadata user password. Consider '
                     'changing it as soon as possible')
        else:
            password = shared_data.get(plugin_constant.SHARED_DATA_PASSWORD)

        return password, injected

    def _set_metadata_password(self, password, service):
        if service.is_password_set:
            LOG.debug('User\'s password already set in the instance metadata '
                      'and it cannot be updated in the instance metadata')
            return True
        else:
            user_pwd_encryption_key = service.get_user_pwd_encryption_key()
            if user_pwd_encryption_key:
                enc_password_b64 = self._encrypt_password(
                    user_pwd_encryption_key, password)
                return service.post_password(enc_password_b64)
            else:
                LOG.info('No SSH public key available for password encryption')
                return True

    def _set_password(self, service, osutils, user_name, shared_data):
        """Change the password for the received username if it is required.

        The used password can be the one received from the metadata provider,
        if it does exist, or a random one will be generated.

        .. notes:
            This method has a different behaviour depending on the value of
            :meth:`~can_update password` if this is True the password will
            be set only if the :meth:`~is_password_changed` is also True.
        """
        if service.can_update_password and not service.is_password_changed():
            LOG.info('Updating password is not required.')
            return None

        password, injected = self._get_password(service, shared_data)
        if not password:
            LOG.debug('Generating a random user password')
            password = osutils.generate_random_password(
                CONF.user_password_length)

        osutils.set_user_password(user_name, password)
        self._change_logon_behaviour(user_name, password_injected=injected)
        return password

    def _change_logon_behaviour(self, username, password_injected=False):
        """Post set password logic

        If the option is activated, force the user to change the
        password at next logon.
        """
        if CONF.first_logon_behaviour == constant.NEVER_CHANGE:
            return

        clear_text = (CONF.first_logon_behaviour ==
                      constant.CLEAR_TEXT_INJECTED_ONLY)
        always = CONF.first_logon_behaviour == constant.ALWAYS_CHANGE
        if always or (clear_text and password_injected):
            osutils = osutils_factory.get_os_utils()
            osutils.change_password_next_logon(username)

    def execute(self, service, shared_data):
        # TODO(alexpilotti): The username selection logic must be set in the
        # CreateUserPlugin instead if using CONF.username
        user_name = shared_data.get(plugin_constant.SHARED_DATA_USERNAME,
                                    CONF.username)

        osutils = osutils_factory.get_os_utils()
        if osutils.user_exists(user_name):
            password = self._set_password(service, osutils,
                                          user_name, shared_data)
            if password:
                LOG.info('Password succesfully updated for user %s' %
                         user_name)
                # TODO(alexpilotti): encrypt with DPAPI
                shared_data[plugin_constant.SHARED_DATA_PASSWORD] = password

                if not service.can_post_password:
                    LOG.info('Cannot set the password in the metadata as it '
                             'is not supported by this service')
                else:
                    self._set_metadata_password(password, service)

        if service.can_update_password:
            # If the metadata provider can update the password, the plugin
            # must run at every boot in order to update the password if
            # it was changed.
            return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False
        else:
            return base.PLUGIN_EXECUTION_DONE, False
