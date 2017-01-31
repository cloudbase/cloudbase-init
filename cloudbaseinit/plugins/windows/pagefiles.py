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
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class PageFilesPlugin(base.BasePlugin):

    def _get_page_file_volumes_by_mount_point(self, osutils):
        page_file_volume_paths = []
        for mount_point in CONF.page_file_volume_mount_points:
            try:
                paths = osutils.get_volume_path_names_by_mount_point(
                    mount_point)
                if paths:
                    page_file_volume_paths.append(paths[0])
            except exception.ItemNotFoundException:
                LOG.info("Mount point not found: %s", mount_point)
        return page_file_volume_paths

    def _get_page_file_volumes_by_label(self, osutils):
        page_file_logical_drives = []
        logical_drives = osutils.get_logical_drives()
        for logical_drive in logical_drives:
            label = osutils.get_volume_label(logical_drive)
            if not label:
                continue
            if label.upper() in [
                    v.upper() for v in CONF.page_file_volume_labels]:
                page_file_logical_drives.append(logical_drive)
        return page_file_logical_drives

    def _get_page_file_volumes(self, osutils):
        return list(set(self._get_page_file_volumes_by_mount_point(osutils)) |
                    set(self._get_page_file_volumes_by_label(osutils)))

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()
        page_file_volumes = sorted(self._get_page_file_volumes(osutils))
        reboot_required = False

        if not page_file_volumes:
            LOG.info("No page file volume found, skipping configuration")
        else:
            page_files = [
                (os.path.join(v, "pagefile.sys"), 0, 0)
                for v in page_file_volumes]

            current_page_files = osutils.get_page_files()
            if sorted(current_page_files) != sorted(page_files):
                osutils.set_page_files(page_files)
                LOG.info("Page file configuration set: %s", page_files)
                reboot_required = True

        return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, reboot_required

    def get_os_requirements(self):
        return 'win32', (5, 2)
