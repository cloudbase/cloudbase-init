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
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseconfigdrive
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import serialization


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class NoCloudConfigDriveService(baseconfigdrive.BaseConfigDriveService):

    def __init__(self):
        super(NoCloudConfigDriveService, self).__init__(
            'cidata', 'meta-data')
        self._meta_data = {}

    def get_user_data(self):
        return self._get_cache_data("user-data")

    def _get_meta_data(self):
        if self._meta_data:
            return self._meta_data

        raw_meta_data = self._get_cache_data("meta-data", decode=True)
        try:
            self._meta_data = (
                serialization.parse_json_yaml(raw_meta_data))
        except base.YamlParserConfigError as ex:
            LOG.error("Metadata could not be parsed")
            LOG.exception(ex)

        return self._meta_data

    def get_host_name(self):
        return self._get_meta_data().get('local-hostname')

    def get_instance_id(self):
        return self._get_meta_data().get('instance-id')

    def get_public_keys(self):
        raw_ssh_keys = self._get_meta_data().get('public-keys')
        if not raw_ssh_keys:
            return []

        return [raw_ssh_keys[key].get('openssh-key') for key in raw_ssh_keys]

    def get_network_details(self):
        debian_net_config = self._get_meta_data().get('network-interfaces')
        if not debian_net_config:
            return None

        return debiface.parse(debian_net_config)
