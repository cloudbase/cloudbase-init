# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the 'License'); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.plugins import base
from cloudbaseinit.plugins import constants
from cloudbaseinit.plugins.windows import x509
from cloudbaseinit.plugins.windows import winrmconfig

LOG = logging.getLogger(__name__)


class ConfigWinRMCertificateAuthPlugin(base.BasePlugin):
    def _get_client_auth_cert(self, service):
        cert_data = None

        meta_data = service.get_meta_data('openstack')
        meta = meta_data.get('meta')

        if meta:
            i = 0
            while True:
                # Chunking is necessary as metadata items can be
                # max. 255 chars long
                cert_chunk = meta.get('admin_cert%d' % i)
                if not cert_chunk:
                    break
                if not cert_data:
                    cert_data = cert_chunk
                else:
                    cert_data += cert_chunk
                i += 1

        if not cert_data:
            # Look if the user_data contains a PEM certificate
            user_data = service.get_user_data('openstack')
            if user_data.startswith(x509.PEM_HEADER):
                cert_data = user_data

        return cert_data

    def _get_credentials(self, shared_data):
        user_name = shared_data.get(constants.SHARED_DATA_USERNAME)
        if not user_name:
            raise Exception("Cannot execute plugin as the username has "
                            "not been set in the plugins shared data")

        password = shared_data.get(constants.SHARED_DATA_PASSWORD)
        if not password:
            raise Exception("Cannot execute plugin as the password has "
                            "not been set in the plugins shared data")

        # For security reasons unset the password in the shared_data
        # as it is currently not needed by other plugins
        shared_data[constants.SHARED_DATA_PASSWORD] = None

        return (user_name, password)

    def execute(self, service, shared_data):
        user_name, password = self._get_credentials(shared_data)

        cert_data = self._get_client_auth_cert(service)
        if not cert_data:
            LOG.info("WinRM certificate authentication cannot be configured "
                     "as a certificate has not been provided in the metadata")
            return (base.PLUGIN_EXECUTION_DONE, False)

        cert_manager = x509.CryptoAPICertManager()
        cert_thumprint, cert_upn = cert_manager.import_cert(
            cert_data, store_name=x509.STORE_NAME_ROOT)

        if not cert_upn:
            LOG.error("WinRM certificate authentication cannot be configured "
                      "as the provided certificate lacks a subject alt name "
                      "containing an UPN (OID 1.3.6.1.4.1.311.20.2.3)")
            return (base.PLUGIN_EXECUTION_DONE, False)

        winrm_config = winrmconfig.WinRMConfig()
        winrm_config.set_auth_config(certificate=True)

        if winrm_config.get_cert_mapping(cert_thumprint, cert_upn):
            winrm_config.delete_cert_mapping(cert_thumprint, cert_upn)
        winrm_config.create_cert_mapping(cert_thumprint, cert_upn,
                                         user_name, password)

        return (base.PLUGIN_EXECUTION_DONE, False)
