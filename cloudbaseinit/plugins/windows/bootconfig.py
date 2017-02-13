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
from cloudbaseinit.utils.windows import bootconfig
from cloudbaseinit.utils.windows import disk

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class BootStatusPolicyPlugin(base.BasePlugin):

    def execute(self, service, shared_data):
        if CONF.bcd_boot_status_policy:
            LOG.info("Configuring boot status policy: %s",
                     CONF.bcd_boot_status_policy)
            bootconfig.set_boot_status_policy(CONF.bcd_boot_status_policy)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (6, 0)


class BCDConfigPlugin(base.BasePlugin):

    @staticmethod
    def _set_unique_disk_id(phys_disk_path):
        # A unique disk ID is needed to avoid disk signature collisions
        # https://blogs.technet.microsoft.com/markrussinovich/2011/11/06/fixing-disk-signature-collisions/
        LOG.info("Setting unique id on disk: %s", phys_disk_path)
        with disk.Disk(phys_disk_path, allow_write=True) as d:
            d.set_unique_id()

    def execute(self, service, shared_data):
        if CONF.set_unique_boot_disk_id:
            if len(bootconfig.get_boot_system_devices()) == 1:
                LOG.info("Configuring boot device")
                bootconfig.set_current_bcd_device_to_boot_partition()
                # TODO(alexpilotti): get disk number from volume
                self._set_unique_disk_id(u"\\\\.\\PHYSICALDRIVE0")

        bootconfig.enable_auto_recovery(CONF.bcd_enable_auto_recovery)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (6, 0)
