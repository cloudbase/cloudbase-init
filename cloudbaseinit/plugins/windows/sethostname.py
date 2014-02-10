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

from oslo.config import cfg

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base

opts = [
    cfg.BoolOpt('netbios_host_name_compatibility', default=True,
                help='Truncates the hostname to 15 characters for Netbios '
                     'compatibility'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

NETBIOS_HOST_NAME_MAX_LEN = 15


class SetHostNamePlugin(base.BasePlugin):
    def execute(self, service, shared_data):
        meta_data = service.get_meta_data('openstack')
        if 'hostname' not in meta_data:
            LOG.debug('Hostname not found in metadata')
            return (base.PLUGIN_EXECUTION_DONE, False)

        osutils = osutils_factory.OSUtilsFactory().get_os_utils()

        metadata_host_name = meta_data['hostname'].split('.', 1)[0]

        if (len(metadata_host_name) > NETBIOS_HOST_NAME_MAX_LEN and
                CONF.netbios_host_name_compatibility):
            new_host_name = metadata_host_name[:NETBIOS_HOST_NAME_MAX_LEN]
            LOG.warn('Truncating host name for Netbios compatibility. '
                     'Old name: %(metadata_host_name)s, new name: '
                     '%(new_host_name)s' %
                     {'metadata_host_name': metadata_host_name,
                      'new_host_name': new_host_name})
        else:
            new_host_name = metadata_host_name

        reboot_required = osutils.set_host_name(new_host_name)

        return (base.PLUGIN_EXECUTION_DONE, reboot_required)
