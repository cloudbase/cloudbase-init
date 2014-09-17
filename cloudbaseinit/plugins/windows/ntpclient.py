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
import time

from oslo.config import cfg

from cloudbaseinit import exception
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base
from cloudbaseinit.utils import dhcp

opts = [
    cfg.BoolOpt('ntp_use_dhcp_config', default=False,
                help='Configures NTP client time synchronization using '
                     'the NTP servers provided via DHCP'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

_W32TIME_SERVICE = "w32time"


class NTPClientPlugin(base.BasePlugin):
    def _check_w32time_svc_status(self, osutils):

        svc_start_mode = osutils.get_service_start_mode(
            _W32TIME_SERVICE)

        if svc_start_mode != osutils.SERVICE_START_MODE_AUTOMATIC:
            osutils.set_service_start_mode(
                _W32TIME_SERVICE,
                osutils.SERVICE_START_MODE_AUTOMATIC)

        svc_status = osutils.get_service_status(_W32TIME_SERVICE)
        if svc_status == osutils.SERVICE_STATUS_STOPPED:
            osutils.start_service(_W32TIME_SERVICE)

            i = 0
            max_retries = 30
            while svc_status != osutils.SERVICE_STATUS_RUNNING:
                if i >= max_retries:
                    raise exception.CloudbaseInitException(
                        'Service %s did not start' % _W32TIME_SERVICE)
                time.sleep(1)
                svc_status = osutils.get_service_status(_W32TIME_SERVICE)
                i += 1

    def execute(self, service, shared_data):
        if CONF.ntp_use_dhcp_config:
            osutils = osutils_factory.get_os_utils()
            dhcp_hosts = osutils.get_dhcp_hosts_in_use()

            ntp_option_data = None

            for (mac_address, dhcp_host) in dhcp_hosts:
                options_data = dhcp.get_dhcp_options(dhcp_host,
                                                     [dhcp.OPTION_NTP_SERVERS])
                if options_data:
                    ntp_option_data = options_data.get(dhcp.OPTION_NTP_SERVERS)
                    if ntp_option_data:
                        break

            if not ntp_option_data:
                LOG.debug("Could not obtain the NTP configuration via DHCP")
                return (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)

            # TODO(alexpilotti): support multiple NTP servers
            ntp_host = socket.inet_ntoa(ntp_option_data[:4])

            self._check_w32time_svc_status(osutils)
            osutils.set_ntp_client_config(ntp_host)

            LOG.info('NTP client configured. Server: %s' % ntp_host)

        return (base.PLUGIN_EXECUTION_DONE, False)
