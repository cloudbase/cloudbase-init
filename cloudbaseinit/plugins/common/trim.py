# Copyright 2017 Cloudbase Solutions Srl
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
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base as plugin_base

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class TrimConfigPlugin(plugin_base.BasePlugin):

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()
        osutils.enable_trim(CONF.trim_enabled)
        LOG.info("TRIM enabled status: %s", CONF.trim_enabled)

        return plugin_base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (6, 1)
