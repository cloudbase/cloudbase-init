# Copyright 2019 VMware, Inc.
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

import base64
import os

from oslo_log import log as oslo_logging
import untangle

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.osutils import factory as osutils_factory

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

INSTANCE_ID = 'iid-ovf'


class OvfService(base.BaseMetadataService):
    def __init__(self):
        super(OvfService, self).__init__()
        self._config_drive_path = None
        self._ovf_env = None
        self._osutils = osutils_factory.get_os_utils()

    def load(self):
        super(OvfService, self).load()

        try:
            self._get_ovf_env()
            return True
        except Exception as ex:
            LOG.exception(ex)
            return False

    def _get_config_drive_path(self):
        if not self._config_drive_path:
            for drive_letter in self._osutils.get_logical_drives():
                label = self._osutils.get_volume_label(drive_letter)
                if label and label.lower() == CONF.ovf.drive_label.lower():
                    self._config_drive_path = drive_letter

            if not self._config_drive_path:
                raise base.NotExistingMetadataException(
                    "No drive with label %s could be found" %
                    CONF.ovf.drive_label)
        return self._config_drive_path

    def _get_ovf_env_path(self):
        drive_path = self._get_config_drive_path()
        ovf_env_path = os.path.join(drive_path, CONF.ovf.config_file_name)

        if not os.path.exists(ovf_env_path):
            raise base.NotExistingMetadataException(
                "File %s does not exist in drive %s" %
                (CONF.ovf.config_file_name, drive_path))

        return ovf_env_path

    def _get_ovf_env(self):
        if not self._ovf_env:
            ovf_env_path = self._get_ovf_env_path()
            self._ovf_env = untangle.parse(ovf_env_path)
        return self._ovf_env

    def _get_property_section(self):
        ovf_env = self._get_ovf_env()
        if not hasattr(ovf_env.Environment, 'PropertySection'):
            LOG.warning("PropertySection not found in ovf file")
            return None
        return ovf_env.Environment.PropertySection

    def _get_property_values(self, property_name):
        prop_values = []
        prop_section = self._get_property_section()
        if not hasattr(prop_section, 'Property'):
            LOG.warning("PropertySection in ovf file has no Property elements")
            return None

        for child_property in prop_section.Property:
            property_key = child_property[CONF.ovf.ns + ':key']
            if property_key and property_key == property_name:
                property_value = child_property[CONF.ovf.ns + ':value']
                if property_value:
                    prop_values.append(property_value.strip())

        if not prop_values:
            LOG.warning("Property %s not found in PropertySection in ovf file",
                        property_name)
        return prop_values

    def _get_property_value(self, property_name):
        prop_values = self._get_property_values(property_name)
        if len(prop_values) >= 1:
            if len(prop_values) > 1:
                LOG.warning("Expected one value for property %s, "
                            "found more. Returning first one",
                            property_name)
            return prop_values[0]
        return None

    def get_instance_id(self):
        instance_id = self._get_property_value('instance-id')
        if instance_id is None:
            instance_id = INSTANCE_ID
        return instance_id

    def get_user_data(self):
        return self._get_property_value('user-data')

    def get_decoded_user_data(self):
        user_data = self.get_user_data()
        if user_data:
            return base64.b64decode(user_data)
        return None

    def get_host_name(self):
        return self._get_property_value('hostname')

    def get_public_keys(self):
        return self._get_property_values('public-keys')

    def get_admin_username(self):
        return self._get_property_value('username')

    def get_admin_password(self):
        return self._get_property_value('password')

    def _get_data(self, path):
        pass
