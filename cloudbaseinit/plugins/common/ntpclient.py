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

import socket

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils import dhcp

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class NTPClientPlugin(base.BasePlugin):
    execution_stage = base.PLUGIN_STAGE_PRE_NETWORKING

    def verify_time_service(self, osutils):
        """Verify that the time service is up.

        Implementing this method is optional, it is
        mostly used by the Windows version of this plugin.
        """

    @staticmethod
    def _unpack_ntp_hosts(ntp_option_data):
        chunks = [ntp_option_data[index: index + 4]
                  for index in range(0, len(ntp_option_data), 4)]
        return list(map(socket.inet_ntoa, chunks))

    def execute(self, service, shared_data):
        reboot_required = False
        osutils = osutils_factory.get_os_utils()

        if osutils.is_real_time_clock_utc() != CONF.real_time_clock_utc:
            osutils.set_real_time_clock_utc(CONF.real_time_clock_utc)
            LOG.info('RTC set to UTC: %s', CONF.real_time_clock_utc)
            reboot_required = True

        if CONF.ntp_enable_service:
            self.verify_time_service(osutils)
            LOG.info('NTP client service enabled')

        if CONF.ntp_use_dhcp_config:
            dhcp_hosts = osutils.get_dhcp_hosts_in_use()

            ntp_option_data = None

            for (_, _, dhcp_host) in dhcp_hosts:
                options_data = dhcp.get_dhcp_options(dhcp_host,
                                                     [dhcp.OPTION_NTP_SERVERS])
                if options_data:
                    ntp_option_data = options_data.get(dhcp.OPTION_NTP_SERVERS)
                    if ntp_option_data:
                        break

            if not ntp_option_data:
                LOG.debug("Could not obtain the NTP configuration via DHCP")
                return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, reboot_required

            ntp_hosts = self._unpack_ntp_hosts(ntp_option_data)
            osutils.set_ntp_client_config(ntp_hosts)
            LOG.info('NTP client configured. Server(s): %s' % ntp_hosts)

        return base.PLUGIN_EXECUTION_DONE, reboot_required
