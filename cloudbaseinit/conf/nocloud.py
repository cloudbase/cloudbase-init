# Copyright 2024 Cloudbase Solutions Srl
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

"""Config options available for the OpenStack metadata service."""

from oslo_config import cfg

from cloudbaseinit.conf import base as conf_base


class NoCloudOptions(conf_base.Options):

    """Config options available for the OpenStack metadata service."""

    def __init__(self, config):
        super(NoCloudOptions, self).__init__(config, group="nocloud")
        self._options = [
            cfg.StrOpt(
                "metadata_file", default="meta-data",
                help="The file name where the service looks for"
                     "metadata"),
            cfg.StrOpt(
                "userdata_file", default="user-data",
                help="The file name where the service looks for"
                     "userdata"),
        ]

    def register(self):
        """Register the current options to the global ConfigOpts object."""
        group = cfg.OptGroup(self.group_name, title='NoCloud Options')
        self._config.register_group(group)
        self._config.register_opts(self._options, group=group)

    def list(self):
        """Return a list which contains all the available options."""
        return self._options
