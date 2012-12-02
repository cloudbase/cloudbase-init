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
import re

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.osutils.factory import *
from cloudbaseinit.plugins.base import *

LOG = logging.getLogger(__name__)

opts = [
    cfg.StrOpt('network_adapter', default=None,
        help='Network adapter to configure. If not specified, the first '
             'available ethernet adapter will be chosen'),
  ]

CONF = cfg.CONF
CONF.register_opts(opts)


class NetworkConfigPlugin():
    def execute(self, service):
        meta_data = service.get_meta_data('openstack')
        if 'network_config' not in meta_data:
            return False
        network_config = meta_data['network_config']
        if 'content_path' not in network_config:
            return False

        content_path = network_config['content_path']
        content_name = content_path.rsplit('/', 1)[-1]
        debian_network_conf = service.get_content('openstack', content_name)

        LOG.debug('network config content:\n%s' % debian_network_conf)

        # TODO (alexpilotti): implement a proper grammar
        m = re.search(r'iface eth0 inet static\s+'
                    'address\s+(?P<address>[^\s]+)\s+'
                    'netmask\s+(?P<netmask>[^\s]+)\s+'
                    'broadcast\s+(?P<broadcast>[^\s]+)\s+'
                    'gateway\s+(?P<gateway>[^\s]+)\s+'
                    'dns\-nameservers\s+(?P<dnsnameservers>[^\r\n]+)\s+', debian_network_conf)
        if not m:
            raise Exception("network_config format not recognized")

        address = m.group('address')
        netmask = m.group('netmask')
        broadcast = m.group('broadcast')
        gateway = m.group('gateway')
        dnsnameservers = m.group('dnsnameservers').strip().split(' ')

        osutils = OSUtilsFactory().get_os_utils()

        network_adapter_name = CONF.network_adapter
        if not network_adapter_name:
            # Get the first available one
            available_adapters = osutils.get_network_adapters()
            if not len(available_adapters):
                raise Exception("No network adapter available")
            network_adapter_name = available_adapters[0]

        LOG.info('Configuring network adapter: \'%s\'' % network_adapter_name)

        reboot_required = osutils.set_static_network_config(
            network_adapter_name, address, netmask, broadcast,
            gateway, dnsnameservers)

        return reboot_required
