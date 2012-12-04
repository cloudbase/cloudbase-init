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

from cloudbaseinit.osutils.factory import *
from cloudbaseinit.plugins.base import *
from cloudbaseinit.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class SetHostNamePlugin(BasePlugin):
    def execute(self, service):
        meta_data = service.get_meta_data('openstack')
        if 'hostname' not in meta_data:
            LOG.debug('Hostname not found in metadata')
            return False

        osutils = OSUtilsFactory().get_os_utils()

        new_host_name = meta_data['hostname'].split('.', 1)[0]
        return osutils.set_host_name(new_host_name)

