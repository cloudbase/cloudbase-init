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
from cloudbaseinit.metadata.services import base as service_base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base as plugin_base
from cloudbaseinit.utils import encoding


LOG = logging.getLogger(__name__)

opts = [
    cfg.StrOpt('network_adapter', default=None, help='Network adapter to '
               'configure. If not specified, the first available ethernet '
               'adapter will be chosen.'),
]

CONF = cfg.CONF
CONF.register_opts(opts)


class NetworkConfigPlugin(plugin_base.BasePlugin):

    def execute(self, service, shared_data):
        # FIXME(cpoieana): `network_config` is deprecated
        # * refactor all services by providing NetworkDetails objects *
        # Also, the old method is not supporting multiple NICs.

        osutils = osutils_factory.get_os_utils()
        network_details = service.get_network_details()
        if not network_details:
            network_config = service.get_network_config()
            if not network_config:
                return (plugin_base.PLUGIN_EXECUTION_DONE, False)

        # ---- BEGIN deprecated code ----
        if not network_details:
            if 'content_path' not in network_config:
                return (plugin_base.PLUGIN_EXECUTION_DONE, False)

            content_path = network_config['content_path']
            content_name = content_path.rsplit('/', 1)[-1]
            debian_network_conf = service.get_content(content_name)
            debian_network_conf = encoding.get_as_string(debian_network_conf)

            LOG.debug('network config content:\n%s' % debian_network_conf)

            # TODO(alexpilotti): implement a proper grammar
            m = re.search(r'iface eth0 inet static\s+'
                          r'address\s+(?P<address>[^\s]+)\s+'
                          r'netmask\s+(?P<netmask>[^\s]+)\s+'
                          r'broadcast\s+(?P<broadcast>[^\s]+)\s+'
                          r'gateway\s+(?P<gateway>[^\s]+)\s+'
                          r'dns\-nameservers\s+'
                          r'(?P<dnsnameservers>[^\r\n]+)\s+',
                          debian_network_conf)
            if not m:
                raise exception.CloudbaseInitException(
                    "network_config format not recognized")

            mac = None
            network_adapters = osutils.get_network_adapters()
            if network_adapters:
                adapter_name = CONF.network_adapter
                if adapter_name:
                    # configure with the specified one
                    for network_adapter in network_adapters:
                        if network_adapter[0] == adapter_name:
                            mac = network_adapter[1]
                            break
                else:
                    # configure with the first one
                    mac = network_adapters[0][1]
            network_details = [
                service_base.NetworkDetails(
                    mac,
                    m.group('address'),
                    m.group('netmask'),
                    m.group('broadcast'),
                    m.group('gateway'),
                    m.group('dnsnameservers').strip().split(' ')
                )
            ]
        # ---- END deprecated code ----

        # check NICs' type and save them by MAC
        macnics = {}
        for nic in network_details:
            if not isinstance(nic, service_base.NetworkDetails):
                raise exception.CloudbaseInitException(
                    "invalid NetworkDetails object {!r}"
                    .format(type(nic))
                )
            # assuming that the MAC address is unique
            macnics[nic.mac] = nic
        # try configuring all the available adapters
        adapter_macs = [pair[1] for pair in
                        osutils.get_network_adapters()]
        if not adapter_macs:
            raise exception.CloudbaseInitException(
                "no network adapters available")
        # configure each one
        reboot_required = False
        configured = False
        for mac in adapter_macs:
            nic = macnics.pop(mac, None)
            if not nic:
                LOG.warn("Missing details for adapter %s", mac)
                continue
            LOG.info("Configuring network adapter %s", mac)
            reboot = osutils.set_static_network_config(
                mac,
                nic.address,
                nic.netmask,
                nic.broadcast,
                nic.gateway,
                nic.dnsnameservers
            )
            reboot_required = reboot or reboot_required
            configured = True
        for mac in macnics:
            LOG.warn("Details not used for adapter %s", mac)
        if not configured:
            LOG.error("No adapters were configured")

        return (plugin_base.PLUGIN_EXECUTION_DONE, reboot_required)
