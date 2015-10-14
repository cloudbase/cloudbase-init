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

import os
import shutil

from oslo_config import cfg
from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.metadata.services.osconfigdrive import factory


# Config Drive types and possible locations.
CD_TYPES = {
    "vfat",    # Visible device (with partition table).
    "iso",     # "Raw" format containing ISO bytes.
}
CD_LOCATIONS = {
    # Look into optical units devices. Only an ISO format could
    # be used here (vfat ignored).
    "cdrom",
    # Search through physical disks for raw ISO content or vfat filesystems
    # containing configuration drive's content.
    "hdd",
    # Search through partitions for raw ISO content or through volumes
    # containing configuration drive's content.
    "partition",
}

opts = [
    cfg.BoolOpt('config_drive_raw_hhd', default=True,
                help='Look for an ISO config drive in raw HDDs',
                deprecated_for_removal=True),
    cfg.BoolOpt('config_drive_cdrom', default=True,
                help='Look for a config drive in the attached cdrom drives',
                deprecated_for_removal=True),
    cfg.BoolOpt('config_drive_vfat', default=True,
                help='Look for a config drive in VFAT filesystems',
                deprecated_for_removal=True),
    cfg.ListOpt('config_drive_types', default=list(CD_TYPES),
                help='Supported formats of a configuration drive'),
    cfg.ListOpt('config_drive_locations', default=list(CD_LOCATIONS),
                help='Supported configuration drive locations'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = oslo_logging.getLogger(__name__)


class ConfigDriveService(baseopenstackservice.BaseOpenStackService):

    def __init__(self):
        super(ConfigDriveService, self).__init__()
        self._metadata_path = None

    def _preprocess_options(self):
        self._searched_types = set(CONF.config_drive_types)
        self._searched_locations = set(CONF.config_drive_locations)

        # Deprecation backward compatibility.
        if CONF.config_drive_raw_hhd:
            self._searched_types.add("iso")
            self._searched_locations.add("hdd")
        if CONF.config_drive_cdrom:
            self._searched_types.add("iso")
            self._searched_locations.add("cdrom")
        if CONF.config_drive_vfat:
            self._searched_types.add("vfat")
            self._searched_locations.add("hdd")

        # Check for invalid option values.
        if self._searched_types | CD_TYPES != CD_TYPES:
            raise exception.CloudbaseInitException(
                "Invalid Config Drive types %s", self._searched_types)
        if self._searched_locations | CD_LOCATIONS != CD_LOCATIONS:
            raise exception.CloudbaseInitException(
                "Invalid Config Drive locations %s", self._searched_locations)

    def load(self):
        super(ConfigDriveService, self).load()

        self._preprocess_options()
        self._mgr = factory.get_config_drive_manager()
        found = self._mgr.get_config_drive_files(
            searched_types=self._searched_types,
            searched_locations=self._searched_locations)

        if found:
            self._metadata_path = self._mgr.target_path
            LOG.debug('Metadata copied to folder: %r', self._metadata_path)
        return found

    def _get_data(self, path):
        norm_path = os.path.normpath(os.path.join(self._metadata_path, path))
        try:
            with open(norm_path, 'rb') as stream:
                return stream.read()
        except IOError:
            raise base.NotExistingMetadataException()

    def cleanup(self):
        LOG.debug('Deleting metadata folder: %r', self._mgr.target_path)
        shutil.rmtree(self._mgr.target_path, ignore_errors=True)
        self._metadata_path = None
