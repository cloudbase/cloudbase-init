# Copyright 2013 Cloudbase Solutions Srl
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
from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import constants
from cloudbaseinit.utils.windows import security
from cloudbaseinit.utils.windows import winrmconfig
from cloudbaseinit.utils.windows import x509


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class ConfigWinRMCertificateAuthPlugin(base.BasePlugin):

    @staticmethod
    def _get_credentials(service, shared_data):
        user_name = shared_data.get(constants.SHARED_DATA_USERNAME,
                                    CONF.username)
        if not user_name:
            raise exception.CloudbaseInitException(
                "Cannot execute plugin as the username has not been set in "
                "the plugins shared data, nor it was found in config file.")

        password = shared_data.get(constants.SHARED_DATA_PASSWORD)
        if not password:
            password = service.get_admin_password()
            if not password:
                raise exception.CloudbaseInitException(
                    "Cannot execute plugin as the password has not been set "
                    "in the plugins shared data, nor it was retrieved "
                    "from the metadata service.")

        # For security reasons unset the password in the shared_data
        # as it is currently not needed by other plugins
        shared_data[constants.SHARED_DATA_PASSWORD] = None

        return user_name, password

    def execute(self, service, shared_data):
        user_name, password = self._get_credentials(service, shared_data)

        certs_data = service.get_client_auth_certs()
        if not certs_data:
            LOG.info("WinRM certificate authentication cannot be configured "
                     "as a certificate has not been provided in the metadata")
            return base.PLUGIN_EXECUTION_DONE, False

        osutils = osutils_factory.get_os_utils()
        security_utils = security.WindowsSecurityUtils()

        # On Windows Vista, 2008, 2008 R2 and 7, changing the configuration of
        # the winrm service will fail with an "Access is denied" error if the
        # User Account Control remote restrictions are enabled.
        # The solution to this issue is to temporarily disable the User Account
        # Control remote restrictions.
        # https://support.microsoft.com/kb/951016
        disable_uac_remote_restrictions = (osutils.check_os_version(6, 0) and
                                           not osutils.check_os_version(6, 2)
                                           and security_utils
                                           .get_uac_remote_restrictions())

        try:
            if disable_uac_remote_restrictions:
                LOG.debug("Disabling UAC remote restrictions")
                security_utils.set_uac_remote_restrictions(enable=False)

            winrm_config = winrmconfig.WinRMConfig()
            winrm_config.set_auth_config(certificate=True)

            for cert_data in certs_data:
                cert_manager = x509.CryptoAPICertManager()
                cert_thumprint, cert_upn = cert_manager.import_cert(
                    cert_data, store_name=x509.STORE_NAME_ROOT)

                if not cert_upn:
                    LOG.error("WinRM certificate authentication cannot be "
                              "configured as the provided certificate lacks a "
                              "subject alt name containing an UPN (OID "
                              "1.3.6.1.4.1.311.20.2.3)")
                    continue

                if winrm_config.get_cert_mapping(cert_thumprint, cert_upn):
                    winrm_config.delete_cert_mapping(cert_thumprint, cert_upn)

                LOG.info("Creating WinRM certificate mapping for user "
                         "%(user_name)s with UPN %(cert_upn)s",
                         {'user_name': user_name, 'cert_upn': cert_upn})
                winrm_config.create_cert_mapping(cert_thumprint, cert_upn,
                                                 user_name, password)

        finally:
            if disable_uac_remote_restrictions:
                LOG.debug("Enabling UAC remote restrictions")
                security_utils.set_uac_remote_restrictions(enable=True)

        return base.PLUGIN_EXECUTION_DONE, False
