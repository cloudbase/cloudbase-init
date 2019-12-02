# Copyright 2019 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging

from cloudbaseinit.osutils import factory
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    base
)

LOG = oslo_logging.getLogger(__name__)


class SetNtpPlugin(base.BaseCloudConfigPlugin):
    """Change the NTP servers according to the cloud-config userdata.

    Following keys can be present:

        enabled: Whether to enable the NTP changes. Defaults to True.
        servers: A list of NTP servers. Defaults to empty list.
        pools: A list of NTP pool servers. Defaults to empty list.

    Pools and servers lists are concatenated and applied to the NTP config.
    """

    def process(self, data):
        ntp_servers = []
        ntp_servers.extend(data.get('servers', []))
        ntp_servers.extend(data.get('pools', []))

        if data.get('enabled', True) and ntp_servers:
            LOG.info("Changing NTP servers to %s." % ntp_servers)
            osutils = factory.get_os_utils()
            osutils.set_ntp_client_config(ntp_servers)

        return False
