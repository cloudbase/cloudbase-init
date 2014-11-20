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

import sys

from oslo.config import cfg

from cloudbaseinit.metadata import factory as metadata_factory
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base as plugins_base
from cloudbaseinit.plugins.common import factory as plugins_factory

opts = [
    cfg.BoolOpt('allow_reboot', default=True, help='Allows OS reboots '
                'requested by plugins'),
    cfg.BoolOpt('stop_service_on_exit', default=True, help='In case of '
                'execution as a service, specifies if the service '
                'must be gracefully stopped before exiting'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


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

        status = self._get_plugin_status(osutils, instance_id, plugin_name)
        if status == plugins_base.PLUGIN_EXECUTION_DONE:
            LOG.debug('Plugin \'%s\' execution already done, skipping',
                      plugin_name)
        else:
            LOG.info('Executing plugin \'%s\'', plugin_name)
            try:
                (status, reboot_required) = plugin.execute(service,
                                                           shared_data)
                self._set_plugin_status(osutils, instance_id, plugin_name,
                                        status)
                return reboot_required
            except Exception as ex:
                LOG.error('plugin \'%(plugin_name)s\' failed with error '
                          '\'%(ex)s\'', {'plugin_name': plugin_name, 'ex': ex})
                LOG.exception(ex)

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

    def configure_host(self):
        osutils = osutils_factory.get_os_utils()
        osutils.wait_for_boot_completion()

        service = metadata_factory.get_metadata_service()
        LOG.info('Metadata service loaded: \'%s\'' %
                 service.get_name())

        instance_id = service.get_instance_id()
        LOG.debug('Instance id: %s', instance_id)

        plugins = plugins_factory.load_plugins()
        plugins_shared_data = {}

        reboot_required = False
        try:
            for plugin in plugins:
                if self._check_plugin_os_requirements(osutils, plugin):
                    if self._exec_plugin(osutils, service, plugin,
                                         instance_id, plugins_shared_data):
                        reboot_required = True
                        if CONF.allow_reboot:
                            break
        finally:
            service.cleanup()

        if reboot_required and CONF.allow_reboot:
            try:
                osutils.reboot()
            except Exception as ex:
                LOG.error('reboot failed with error \'%s\'' % ex)
        elif CONF.stop_service_on_exit:
            osutils.terminate()
