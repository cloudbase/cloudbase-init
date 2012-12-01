# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import logging
import uuid

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.osutils.factory import *
from cloudbaseinit.plugins.base import *

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


class CreateUserPlugin(BasePlugin):
    def execute(self, service):
        username = CONF.username

        meta_data = service.get_meta_data('openstack')
        if 'admin_pass' in meta_data and CONF.inject_user_password:
            password = meta_data['admin_pass']
        else:
            password = None

        osutils = OSUtilsFactory().get_os_utils()
        if not osutils.user_exists(username):
            if not password:
                # Generate a random password
                # Limit to 14 chars for compatibility with NT
                LOG.debug("Generating a random password")
                password = str(uuid.uuid4()).replace('-', '')[:14]

            osutils.create_user(username, password)
        else:
            if password:
                osutils.set_user_password(username, password)

        if password:
            # Create a user profile in order for other plugins
            # to access the user home, etc
            token = osutils.create_user_logon_session(username, password, True)
            osutils.close_user_logon_session(token)

        for group in CONF.groups:
            try:
                osutils.add_user_to_local_group(username, group)
            except Exception, ex:
                LOG.error('Cannot add user to group \'%(group)s\'. '
                    'Error: %(ex)s' % locals())

        return False
