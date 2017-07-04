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

import functools
import os
import sys

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata import factory as metadata_factory
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base as plugins_base
from cloudbaseinit.plugins import factory as plugins_factory
from cloudbaseinit.utils import log as logging
from cloudbaseinit import version


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class InitManager(object):
    _PLUGINS_CONFIG_SECTION = 'Plugins'

    def _get_plugins_section(self, instance_id):
        if not instance_id:
            return self._PLUGINS_CONFIG_SECTION
        else:
            return instance_id + "/" + self._PLUGINS_CONFIG_SECTION

    def _get_plugin_status(self, osutils, instance_id, plugin_name):
        return osutils.get_config_value(plugin_name,
                                        self._get_plugins_section(instance_id))

    def _set_plugin_status(self, osutils, instance_id, plugin_name, status):
        osutils.set_config_value(plugin_name, status,
                                 self._get_plugins_section(instance_id))

    def _exec_plugin(self, osutils, service, plugin, instance_id, shared_data):
        plugin_name = plugin.get_name()

        reboot_required = None
        success = True
        status = None
        if instance_id is not None:
            status = self._get_plugin_status(osutils, instance_id, plugin_name)
        if status == plugins_base.PLUGIN_EXECUTION_DONE:
            LOG.debug('Plugin \'%s\' execution already done, skipping',
                      plugin_name)
        else:
            LOG.info('Executing plugin \'%s\'', plugin_name)
            try:
                (status, reboot_required) = plugin.execute(service,
                                                           shared_data)
                if instance_id is not None:
                    self._set_plugin_status(osutils, instance_id, plugin_name,
                                            status)
            except Exception as ex:
                LOG.error('plugin \'%(plugin_name)s\' failed with error '
                          '\'%(ex)s\'', {'plugin_name': plugin_name, 'ex': ex})
                LOG.exception(ex)
                success = False
        return success, reboot_required

    def _check_plugin_os_requirements(self, osutils, plugin):
        supported = False
        plugin_name = plugin.get_name()

        (required_platform, min_os_version) = plugin.get_os_requirements()
        if required_platform and sys.platform != required_platform:
            LOG.debug('Skipping plugin: \'%s\'. Platform not supported' %
                      plugin_name)
        else:
            if not min_os_version:
                supported = True
            else:
                os_major, os_minor = min_os_version
                if osutils.check_os_version(os_major, os_minor):
                    supported = True
                else:
                    LOG.debug('Skipping plugin: \'%s\'. OS version not '
                              'supported' % plugin_name)
        return supported

    @staticmethod
    def _check_latest_version():
        if CONF.check_latest_version:
            log_version = functools.partial(
                LOG.info, 'Found new version of cloudbase-init %s')
            version.check_latest_version(log_version)

    def _handle_plugins_stage(self, osutils, service, instance_id, stage):
        plugins_shared_data = {}
        reboot_required = False
        stage_success = True
        plugins = plugins_factory.load_plugins(stage)

        LOG.info('Executing plugins for stage %r:', stage)

        for plugin in plugins:
            if self._check_plugin_os_requirements(osutils, plugin):
                success, reboot_required = self._exec_plugin(
                    osutils, service, plugin, instance_id,
                    plugins_shared_data)
                if not success:
                    stage_success = False
                if reboot_required and CONF.allow_reboot:
                        break

        return stage_success, reboot_required

    @staticmethod
    def _reset_service_password_and_respawn(osutils):
        """Avoid pass the hash attacks from cloned instances."""
        credentials = osutils.reset_service_password()
        if not credentials:
            return

        service_domain, service_user, service_password = credentials
        _, current_user = osutils.get_current_user()
        # Notes(alexcoman): No need to check domain as password reset applies
        # to local users only.
        if current_user != service_user:
            LOG.debug("No need to respawn process. Current user: "
                      "%(current_user)s. Service user: "
                      "%(service_user)s",
                      {"current_user": current_user,
                       "service_user": service_user})
            return

        # Note(alexcoman): In order to avoid conflicts caused by the logging
        # handlers being shared between the current process and the new one,
        # any logging handlers for the current logger object will be closed.
        # By doing so, the next time the logger is called, it will be created
        # under the newly updated process, thus avoiding any issues or
        # conflicts where the logging can't be done.
        logging.release_logging_handlers("cloudbaseinit")

        # Note(alexcoman): In some edge cases the sys.args doesn't contain
        # the python executable. In order to avoid this kind of issue the
        # sys.executable will be injected into the arguments if it's necessary.
        arguments = sys.argv + ["--noreset_service_password"]
        if os.path.basename(arguments[0]).endswith(".py"):
            arguments.insert(0, sys.executable)

        LOG.info("Respawning current process with updated credentials.")
        token = osutils.create_user_logon_session(
            service_user, service_password, service_domain,
            logon_type=osutils.LOGON32_LOGON_BATCH)
        exit_code = osutils.execute_process_as_user(token, arguments)
        LOG.info("Process execution ended with exit code: %s", exit_code)
        sys.exit(exit_code)

    def configure_host(self):
        service = None
        osutils = osutils_factory.get_os_utils()

        if CONF.reset_service_password and sys.platform == 'win32':
            self._reset_service_password_and_respawn(osutils)

        LOG.info('Cloudbase-Init version: %s', version.get_version())
        osutils.wait_for_boot_completion()

        stage_success, reboot_required = self._handle_plugins_stage(
            osutils, None, None,
            plugins_base.PLUGIN_STAGE_PRE_NETWORKING)

        self._check_latest_version()

        if not (reboot_required and CONF.allow_reboot):
            stage_success, reboot_required = self._handle_plugins_stage(
                osutils, None, None,
                plugins_base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY)

        if not (reboot_required and CONF.allow_reboot):
            try:
                service = metadata_factory.get_metadata_service()
            except exception.MetadataNotFoundException:
                LOG.error("No metadata service found")
        if service:
            LOG.info('Metadata service loaded: \'%s\'' %
                     service.get_name())

            if CONF.metadata_report_provisioning_started:
                LOG.info("Reporting provisioning started")
                service.provisioning_started()

            instance_id = service.get_instance_id()
            LOG.debug('Instance id: %s', instance_id)

            try:
                stage_success, reboot_required = self._handle_plugins_stage(
                    osutils, service, instance_id,
                    plugins_base.PLUGIN_STAGE_MAIN)
            finally:
                service.cleanup()

            if (CONF.metadata_report_provisioning_completed and
                    not stage_success):
                try:
                    LOG.info("Reporting provisioning failed")
                    service.provisioning_failed()
                except Exception as ex:
                    LOG.exception(ex)

        if reboot_required and CONF.allow_reboot:
            try:
                LOG.info("Rebooting")
                osutils.reboot()
            except Exception as ex:
                LOG.error('reboot failed with error \'%s\'' % ex)
        else:
            LOG.info("Plugins execution done")

            if (service and CONF.metadata_report_provisioning_completed and
                    stage_success):
                try:
                    LOG.info("Reporting provisioning completed")
                    service.provisioning_completed()
                except Exception as ex:
                    LOG.exception(ex)

            if CONF.stop_service_on_exit:
                LOG.info("Stopping Cloudbase-Init service")
                osutils.terminate()
