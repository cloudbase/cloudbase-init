# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from cloudbaseinit.metadata.factory import *
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils.factory import *
from cloudbaseinit.plugins.factory import *
from cloudbaseinit.utils import *

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class InitManager(object):
    _config_done_key = 'config_done'

    def _is_already_configured(self, osutils):
        return osutils.get_config_value(self._config_done_key) == 1

    def _mark_as_configured(self, osutils):
        osutils.set_config_value(self._config_done_key, 1)
        
    def configure_host(self):
        osutils = OSUtilsFactory().get_os_utils()
        
        if self._is_already_configured(osutils):
            LOG.info('Host already configured, skipping configuration')
            return
        
        plugins = PluginFactory().load_plugins()
        service = MetadataServiceFactory().get_metadata_service()
        LOG.info('Metadata service loaded: \'%s\'' %
            service.__class__.__name__)

        reboot_required = False
        try:
            for plugin in plugins:
                plugin_name = plugin.__class__.__name__
                LOG.info('Executing plugin \'%(plugin_name)s\'' % locals())
                try:
                    plugin_requires_reboot = plugin.execute(service)
                    if plugin_requires_reboot:
                        reboot_required = True
                except Exception, ex:
                    LOG.error('plugin \'%(plugin_name)s\' failed '
                        'with error \'%(ex)s\'' % locals())
        finally:
            service.cleanup()

        self._mark_as_configured(osutils)
            
        if reboot_required:
            try:
                osutils.reboot()
            except Exception, ex:
                LOG.error('reboot failed with error \'%s\'' % ex)
