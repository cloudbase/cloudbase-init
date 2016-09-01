# Copyright (c) 2013 Cloudbase Solutions Srl
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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows.storage import factory as storage_factory

CONF = cloudbaseinit_conf.CONF


class ExtendVolumesPlugin(base.BasePlugin):
    def _get_volumes_to_extend(self):
        if CONF.volumes_to_extend is not None:
            return list(map(int, CONF.volumes_to_extend))

    def execute(self, service, shared_data):
        volumes_indexes = self._get_volumes_to_extend()
        storage_manager = storage_factory.get_storage_manager()
        storage_manager.extend_volumes(volumes_indexes)

        return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False

    def get_os_requirements(self):
        return 'win32', (5, 2)
