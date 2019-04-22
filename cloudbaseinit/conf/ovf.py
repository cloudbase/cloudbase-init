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

"""Config options available for the Ovf metadata service."""

from oslo_config import cfg

from cloudbaseinit.conf import base as conf_base


class OvfOptions(conf_base.Options):

    """Config options available for the Ovf metadata service."""

    def __init__(self, config):
        super(OvfOptions, self).__init__(config, group="ovf")
        self._options = [
            cfg.StrOpt(
                "config_file_name",
                default="ovf-env.xml",
                help="Configuration file name"),
            cfg.StrOpt(
                "drive_label",
                default="OVF ENV",
                help="Look for configuration file in drives with this label"),
            cfg.StrOpt(
                "ns",
                default="oe",
                help="Namespace prefix for ovf environment"),
        ]

    def register(self):
        """Register the current options to the global ConfigOpts object."""
        group = cfg.OptGroup(self.group_name, title='Ovf Options')
        self._config.register_group(group)
        self._config.register_opts(self._options, group=group)

    def list(self):
        """Return a list which contains all the available options."""
        return self._options
