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

from oslo.config import cfg

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base
from cloudbaseinit.plugins import constants

CONF = cfg.CONF
CONF.import_opt('username', 'cloudbaseinit.plugins.windows.createuser')

LOG = logging.getLogger(__name__)


class SetUserPasswordPlugin(base.BasePlugin):
    """
    Version of setuserpassword.SetUserPasswordPlugin that works with
    CloudStack its password management logic.
    """
    @staticmethod
    def _get_password(service):
        return service.get_admin_password()

    def _set_password(self, service, os_utils, user_name):
        password = self._get_password(service)
        LOG.info('Setting the user\'s password')
        os_utils.set_user_password(user_name, password)
        return password

    @staticmethod
    def _notify_saved_password(service):
        return service.notify_saved_password()

    def execute(self, service, shared_data):
        if not service.__class__.__name__.endswith("CloudStack"):
            LOG.warn('Invoked cloudstack password plugin but service is not cloudstack')
            # be optimistic... return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False

        user_name = shared_data.get(constants.SHARED_DATA_USERNAME, CONF.username)
        os_utils = osutils_factory.get_os_utils()
        if not os_utils.user_exists(user_name):
            LOG.warn('Invoked cloudstack password plugin but user %s does not exist' % user_name)
            return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False

        password = self._set_password(service, os_utils, user_name)
        shared_data[constants.SHARED_DATA_PASSWORD] = password
        self._notify_saved_password(service)
        return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False
        # we want to be able to re-re-reset the password
        #   return base.PLUGIN_EXECUTION_DONE, False
