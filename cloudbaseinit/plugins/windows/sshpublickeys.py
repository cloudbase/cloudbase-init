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
import os

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.osutils.factory import *
from cloudbaseinit.plugins.base import *

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class SetUserSSHPublicKeysPlugin(BasePlugin):
    def execute(self, service):
        meta_data = service.get_meta_data('openstack')
        if not 'public_keys' in meta_data:
            return False

        username = CONF.username

        osutils = OSUtilsFactory().get_os_utils()
        user_home = osutils.get_user_home(username)

        if not user_home:
            raise Exception("User profile not found!")

        LOG.debug("User home: %s" % user_home)

        user_ssh_dir = os.path.join(user_home, '.ssh')
        if not os.path.exists(user_ssh_dir):
            os.makedirs(user_ssh_dir)

        authorized_keys_path = os.path.join(user_ssh_dir, "authorized_keys")
        with open(authorized_keys_path, 'w') as f:
            public_keys = meta_data['public_keys']
            for k in public_keys:
                f.write(public_keys[k])
