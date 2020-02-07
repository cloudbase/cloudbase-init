# Copyright 2020 Cloudbase Solutions Srl
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
from cloudbaseinit.metadata.services import baseconfigdrive
from cloudbaseinit.metadata.services import baseopenstackservice

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class ConfigDriveService(baseconfigdrive.BaseConfigDriveService,
                         baseopenstackservice.BaseOpenStackService):

    def __init__(self):
        super(ConfigDriveService, self).__init__(
            'config-2', 'openstack\\latest\\meta_data.json')
