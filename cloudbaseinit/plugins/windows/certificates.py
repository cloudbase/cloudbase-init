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
from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows import x509

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class ServerCertificatesPlugin(base.BasePlugin):
    @staticmethod
    def _use_machine_keyset(store_location):
        if store_location == constant.CERT_LOCATION_LOCAL_MACHINE:
            return True
        elif store_location == constant.CERT_LOCATION_CURRENT_USER:
            return False
        else:
            raise exception.ItemNotFoundException(
                "Unsupported certificate store location: %s" %
                store_location)

    def execute(self, service, shared_data):
        certs_info = service.get_server_certs()

        if certs_info is None:
            LOG.info("The metadata service does not provide server "
                     "certificates")
        else:
            cert_mgr = x509.CryptoAPICertManager()
            for cert_info in service.get_server_certs():
                cert_name = cert_info.get("name")
                store_location = cert_info.get("store_location")
                store_name = cert_info.get("store_name")
                pfx_data = cert_info.get("pfx_data")
                machine_keyset = self._use_machine_keyset(store_location)
                pfx_password = None

                LOG.info("Importing PFX certificate %(cert_name)s in store "
                         "%(store_location)s, %(store_name)s",
                         {"cert_name": cert_name,
                          "store_location": store_location,
                          "store_name": store_name})
                cert_mgr.import_pfx_certificate(
                    pfx_data, pfx_password, machine_keyset, store_name)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (5, 2)
