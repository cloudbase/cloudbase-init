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

import re

from oslo.config import cfg

from cloudbaseinit import exception
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base

LOG = logging.getLogger(__name__)

opts = [
    cfg.StrOpt('network_adapter', default=None, help='Network adapter to '
               'configure. If not specified, the first available ethernet '
               'adapter will be chosen'),
]

CONF = cfg.CONF
CONF.register_opts(opts)


class NetworkConfigPlugin(base.BasePlugin):
    def execute(self, service, shared_data):
        network_config = service.get_network_config()
        if not network_config:
            return (base.PLUGIN_EXECUTION_DONE, False)

        if 'content_path' not in network_config:
            return (base.PLUGIN_EXECUTION_DONE, False)

        content_path = network_config['content_path']
        content_name = content_path.rsplit('/', 1)[-1]
        debian_network_conf = service.get_content(content_name)

        LOG.debug('network config content:\n%s' % debian_network_conf)

        # TODO(alexpilotti): implement a proper grammar
        m = re.search(r'iface eth0 inet static\s+'
                      r'address\s+(?P<address>[^\s]+)\s+'
                      r'netmask\s+(?P<netmask>[^\s]+)\s+'
                      r'broadcast\s+(?P<broadcast>[^\s]+)\s+'
                      r'gateway\s+(?P<gateway>[^\s]+)\s+'
                      r'dns\-nameservers\s+(?P<dnsnameservers>[^\r\n]+)\s+',
                      debian_network_conf)
        if not m:
            raise exception.CloudbaseInitException(
                "network_config format not recognized")

        address = m.group('address')
        netmask = m.group('netmask')
        broadcast = m.group('broadcast')
        gateway = m.group('gateway')
        dnsnameservers = m.group('dnsnameservers').strip().split(' ')

        osutils = osutils_factory.get_os_utils()

        network_adapter_name = CONF.network_adapter
        if not network_adapter_name:
            # Get the first available one
            available_adapters = osutils.get_network_adapters()
            if not len(available_adapters):
                raise exception.CloudbaseInitException(
                    "No network adapter available")
            network_adapter_name = available_adapters[0]

        LOG.info('Configuring network adapter: \'%s\'' % network_adapter_name)

        reboot_required = osutils.set_static_network_config(
            network_adapter_name, address, netmask, broadcast,
            gateway, dnsnameservers)

        return (base.PLUGIN_EXECUTION_DONE, reboot_required)
