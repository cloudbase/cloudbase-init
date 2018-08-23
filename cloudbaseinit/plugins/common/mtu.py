# Copyright 2014 Cloudbase Solutions Srl
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

import struct

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils import dhcp

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class MTUPlugin(base.BasePlugin):
    execution_stage = base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY

    def execute(self, service, shared_data):
        if CONF.mtu_use_dhcp_config:
            osutils = osutils_factory.get_os_utils()
            dhcp_hosts = osutils.get_dhcp_hosts_in_use()

            for (adapter_name, mac_address, dhcp_host) in dhcp_hosts:
                options_data = dhcp.get_dhcp_options(dhcp_host,
                                                     [dhcp.OPTION_MTU])
                if options_data:
                    mtu_option_data = options_data.get(dhcp.OPTION_MTU)
                    if mtu_option_data:
                        mtu = struct.unpack('!H', mtu_option_data)[0]
                        osutils.set_network_adapter_mtu(adapter_name, mtu)
                    else:
                        LOG.debug('Could not obtain the MTU configuration '
                                  'via DHCP for interface "%s"' % mac_address)

        return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False
