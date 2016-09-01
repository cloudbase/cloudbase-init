# Copyright 2016 Cloudbase Solutions Srl
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

"""Config options available for the cloud config metadata service."""

from oslo_config import cfg

from cloudbaseinit.conf import base as conf_base
from cloudbaseinit import constant


class CloudConfigOptions(conf_base.Options):

    """Config options available for the cloud config metadata service."""

    def __init__(self, config):
        super(CloudConfigOptions, self).__init__(config, group="config_drive")
        self._options = [
            cfg.BoolOpt(
                "raw_hdd", default=True,
                help="Look for an ISO config drive in raw HDDs",
                deprecated_name="config_drive_raw_hhd",
                deprecated_group="DEFAULT",
                deprecated_for_removal=True),
            cfg.BoolOpt(
                "cdrom", default=True,
                help="Look for a config drive in the attached cdrom drives",
                deprecated_name="config_drive_cdrom",
                deprecated_group="DEFAULT",
                deprecated_for_removal=True),
            cfg.BoolOpt(
                "vfat", default=True,
                help="Look for a config drive in VFAT filesystems",
                deprecated_name="config_drive_vfat",
                deprecated_group="DEFAULT",
                deprecated_for_removal=True),
            cfg.ListOpt(
                "types", default=list(constant.CD_TYPES),
                help="Supported formats of a configuration drive",
                deprecated_name="config_drive_types",
                deprecated_group="DEFAULT",),
            cfg.ListOpt(
                "locations", default=list(constant.CD_LOCATIONS),
                deprecated_name="config_drive_locations",
                deprecated_group="DEFAULT",
                help="Supported configuration drive locations"),
        ]

    def register(self):
        """Register the current options to the global ConfigOpts object."""
        group = cfg.OptGroup(self._group_name, title='Cloud Config Options')
        self._config.register_group(group)
        self._config.register_opts(self._options, group=group)

    def list(self):
        """Return a list which contains all the available options."""
        return self._options
