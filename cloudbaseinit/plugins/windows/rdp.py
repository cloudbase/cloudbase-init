# Copyright (c) 2017 Cloudbase Solutions Srl
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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows import rdp

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class RDPSettingsPlugin(base.BasePlugin):

    def execute(self, service, shared_data):
        LOG.info("Setting RDP KeepAlive: %s", CONF.rdp_set_keepalive)
        rdp.set_rdp_keepalive(CONF.rdp_set_keepalive)
        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (5, 2)


class RDPPostCertificateThumbprintPlugin(base.BasePlugin):

    def execute(self, service, shared_data):
        if not service.can_post_rdp_cert_thumbprint:
            LOG.info("The service does not provide the capability to post "
                     "the RDP certificate thumbprint")
        else:
            cert_thumb = rdp.get_rdp_certificate_thumbprint()
            LOG.info("Posting the RDP certificate thumbprint: %s", cert_thumb)
            service.post_rdp_cert_thumbprint(cert_thumb)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (5, 2)
