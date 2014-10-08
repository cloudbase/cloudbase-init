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

import os
import shutil
import tempfile
import uuid

from oslo.config import cfg

from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.metadata.services.osconfigdrive import factory
from cloudbaseinit.openstack.common import log as logging

opts = [
    cfg.BoolOpt('config_drive_raw_hhd', default=True,
                help='Look for an ISO config drive in raw HDDs'),
    cfg.BoolOpt('config_drive_cdrom', default=True,
                help='Look for a config drive in the attached cdrom drives'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class ConfigDriveService(baseopenstackservice.BaseOpenStackService):
    def __init__(self):
        super(ConfigDriveService, self).__init__()
        self._metadata_path = None

    def load(self):
        super(ConfigDriveService, self).load()

        target_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))

        mgr = factory.get_config_drive_manager()
        found = mgr.get_config_drive_files(target_path,
                                           CONF.config_drive_raw_hhd,
                                           CONF.config_drive_cdrom)
        if found:
            self._metadata_path = target_path
            LOG.debug('Metadata copied to folder: \'%s\'' %
                      self._metadata_path)
        return found

    def _get_data(self, path):
        norm_path = os.path.normpath(os.path.join(self._metadata_path, path))
        try:
            with open(norm_path, 'rb') as f:
                return f.read()
        except IOError:
            raise base.NotExistingMetadataException()

    def cleanup(self):
        if self._metadata_path:
            LOG.debug('Deleting metadata folder: \'%s\'' % self._metadata_path)
            shutil.rmtree(self._metadata_path, ignore_errors=True)
            self._metadata_path = None
