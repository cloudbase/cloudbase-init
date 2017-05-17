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

import contextlib

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows import security
from cloudbaseinit.utils.windows import winrmconfig
from cloudbaseinit.utils.windows import x509


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class ConfigWinRMListenerPlugin(base.BasePlugin):
    _cert_subject = "CN=Cloudbase-Init WinRM"
    _winrm_service_name = "WinRM"

    def _check_winrm_service(self, osutils):
        if not osutils.check_service_exists(self._winrm_service_name):
            LOG.warn("Cannot configure the WinRM listener as the service "
                     "is not available")
            return False

        start_mode = osutils.get_service_start_mode(self._winrm_service_name)
        if start_mode in [osutils.SERVICE_START_MODE_MANUAL,
                          osutils.SERVICE_START_MODE_DISABLED]:
            # TODO(alexpilotti) Set to "Delayed Start"
            osutils.set_service_start_mode(
                self._winrm_service_name,
                osutils.SERVICE_START_MODE_AUTOMATIC)

        service_status = osutils.get_service_status(self._winrm_service_name)
        if service_status == osutils.SERVICE_STATUS_STOPPED:
            osutils.start_service(self._winrm_service_name)

        return True

    @contextlib.contextmanager
    def _check_uac_remote_restrictions(self, osutils):
        security_utils = security.WindowsSecurityUtils()
        # On Windows Vista, 2008, 2008 R2 and 7, changing the configuration of
        # the winrm service will fail with an "Access is denied" error if the
        # User Account Control remote restrictions are enabled.
        # The solution to this issue is to temporarily disable the User Account
        # Control remote restrictions.
        # https://support.microsoft.com/kb/951016
        disable_uac_remote_restrictions = (
            osutils.check_os_version(6, 0) and
            not osutils.check_os_version(6, 2) and
            security_utils.get_uac_remote_restrictions())
        try:
            if disable_uac_remote_restrictions:
                LOG.debug("Disabling UAC remote restrictions")
                security_utils.set_uac_remote_restrictions(enable=False)
            yield
        finally:
            if disable_uac_remote_restrictions:
                LOG.debug("Enabling UAC remote restrictions")
                security_utils.set_uac_remote_restrictions(enable=True)

    def _configure_winrm_listener(self, osutils, winrm_config, protocol,
                                  cert_thumbprint=None):
        if winrm_config.get_listener(protocol=protocol):
            winrm_config.delete_listener(protocol=protocol)

        winrm_config.create_listener(cert_thumbprint=cert_thumbprint,
                                     protocol=protocol)

        listener_config = winrm_config.get_listener(protocol=protocol)
        listener_port = listener_config.get("Port")

        rule_name = "WinRM %s" % protocol
        osutils.firewall_create_rule(rule_name, listener_port,
                                     osutils.PROTOCOL_TCP)

    def _get_winrm_listeners_config(self, service):
        listeners_config = service.get_winrm_listeners_configuration()
        if listeners_config is None:
            listeners_config = []
            if CONF.winrm_configure_http_listener:
                listeners_config.append(
                    {"protocol": winrmconfig.LISTENER_PROTOCOL_HTTP})
            if CONF.winrm_configure_https_listener:
                listeners_config.append(
                    {"protocol": winrmconfig.LISTENER_PROTOCOL_HTTPS})
        return listeners_config

    def _create_self_signed_certificate(self):
        LOG.info("Generating self signed certificate for WinRM HTTPS listener")
        cert_manager = x509.CryptoAPICertManager()
        cert_thumbprint, _ = cert_manager.create_self_signed_cert(
            self._cert_subject)
        return cert_thumbprint

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()

        if not self._check_winrm_service(osutils):
            return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False

        listeners_config = self._get_winrm_listeners_config(service)

        if not listeners_config:
            LOG.info("No WinRM listener configuration provided")
        else:
            with self._check_uac_remote_restrictions(osutils):
                winrm_config = winrmconfig.WinRMConfig()
                winrm_config.set_auth_config(
                    basic=CONF.winrm_enable_basic_auth)

                for listener_config in listeners_config:
                    protocol = listener_config["protocol"].upper()

                    cert_thumb = None
                    if protocol == winrmconfig.LISTENER_PROTOCOL_HTTPS:
                        cert_thumb = listener_config.get(
                            "certificate_thumbprint")
                        if not cert_thumb:
                            cert_thumb = self._create_self_signed_certificate()

                    LOG.info("Configuring WinRM listener for protocol: "
                             "%(protocol)s, certificate thumbprint: "
                             "%(cert_thumb)s",
                             {"protocol": protocol,
                              "cert_thumb": cert_thumb})
                    self._configure_winrm_listener(
                        osutils, winrm_config, protocol, cert_thumb)

        return base.PLUGIN_EXECUTION_DONE, False
