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

import os

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base as metadata_services_base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class EphemeralDiskPlugin(base.BasePlugin):
    @staticmethod
    def _get_ephemeral_disk_volume_by_mount_point(osutils):
        if CONF.ephemeral_disk_volume_mount_point:
            try:
                paths = osutils.get_volume_path_names_by_mount_point(
                    CONF.ephemeral_disk_volume_mount_point)
                if paths:
                    return paths[0]
            except exception.ItemNotFoundException:
                LOG.debug("Ephemeral disk mount point not found: %s",
                          CONF.ephemeral_disk_volume_mount_point)

    @staticmethod
    def _get_ephemeral_disk_volume_by_label(osutils):
        if CONF.ephemeral_disk_volume_label:
            logical_drives = osutils.get_logical_drives()
            for logical_drive in logical_drives:
                label = osutils.get_volume_label(logical_drive)
                if not label:
                    continue
                if label.upper() == CONF.ephemeral_disk_volume_label.upper():
                    return logical_drive

    def _get_ephemeral_disk_volume_path(self, osutils):
        return (self._get_ephemeral_disk_volume_by_mount_point(osutils) or
                self._get_ephemeral_disk_volume_by_label(osutils))

    def _set_ephemeral_disk_data_loss_warning(self, service,
                                              disk_warning_path):
        LOG.debug("Setting ephemeral disk data loss warning: %s",
                  disk_warning_path)
        data_loss_warning = b''
        try:
            data_loss_warning = service.get_ephemeral_disk_data_loss_warning()
        except metadata_services_base.NotExistingMetadataException:
            LOG.debug("Metadata service does not provide an ephemeral "
                      "disk data loss warning content")
        with open(disk_warning_path, 'wb') as f:
            f.write(data_loss_warning)

    def execute(self, service, shared_data):

        try:
            service.get_ephemeral_disk_data_loss_warning()
        except metadata_services_base.NotExistingMetadataException:
            return base.PLUGIN_EXECUTION_DONE, False

        osutils = osutils_factory.get_os_utils()
        ephemeral_disk_volume_path = self._get_ephemeral_disk_volume_path(
            osutils)

        if not ephemeral_disk_volume_path:
            LOG.info("Ephemeral disk volume not found")
        else:
            if CONF.ephemeral_disk_data_loss_warning_path:
                disk_warning_path = os.path.join(
                    ephemeral_disk_volume_path,
                    CONF.ephemeral_disk_data_loss_warning_path)
                self._set_ephemeral_disk_data_loss_warning(
                    service, disk_warning_path)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (5, 2)
