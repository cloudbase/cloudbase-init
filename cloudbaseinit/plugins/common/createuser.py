# Copyright 2012 Cloudbase Solutions Srl
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

import abc

from oslo_log import log as oslo_logging
import six

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import constants

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseCreateUserPlugin(base.BasePlugin):
    """This is a base class for creating or modifying an user."""

    @abc.abstractmethod
    def create_user(self, username, password, osutils):
        """Create a new username, with the given *username*.

        This will be called by :meth:`~execute`, whenever
        a new user must be created.
        """

    @abc.abstractmethod
    def post_create_user(self, user_name, password, osutils):
        """Executes post user creation logic.

        This will be called after by :meth:`~execute`, after
        the user is created or the user password is updated.
        """

    @staticmethod
    def _get_password(osutils):
        # Generate a temporary random password to be replaced
        # by SetUserPasswordPlugin (starting from Grizzly)
        return osutils.generate_random_password(CONF.user_password_length)

    def execute(self, service, shared_data):
        user_name = service.get_admin_username() or CONF.username
        shared_data[constants.SHARED_DATA_USERNAME] = user_name

        osutils = osutils_factory.get_os_utils()
        password = self._get_password(osutils)

        if CONF.rename_admin_user:
            admin_user_name = [u for u in osutils.enum_users()
                               if osutils.is_builtin_admin(u)][0]

            if admin_user_name.lower() != user_name.lower():
                LOG.info('Renaming builtin admin user "%(admin_user_name)s" '
                         'to %(new_user_name)s and setting password',
                         {'admin_user_name': admin_user_name,
                          'new_user_name': user_name})
                osutils.rename_user(admin_user_name, user_name)
                osutils.set_user_password(user_name, password)
            else:
                LOG.info('"%s" is already the name of the builtin admin '
                         'user, skipping renaming', user_name)
        elif osutils.user_exists(user_name):
            LOG.info('Setting password for existing user "%s"', user_name)
            osutils.set_user_password(user_name, password)
        else:
            LOG.info('Creating user "%s" and setting password', user_name)
            self.create_user(user_name, password, osutils)

            # TODO(alexpilotti): encrypt with DPAPI
            shared_data[constants.SHARED_DATA_PASSWORD] = password

        self.post_create_user(user_name, password, osutils)

        for group_name in CONF.groups:
            try:
                osutils.add_user_to_local_group(user_name, group_name)
            except Exception:
                LOG.exception('Cannot add user to group "%s"', group_name)

        return base.PLUGIN_EXECUTION_DONE, False
