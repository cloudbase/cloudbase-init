# Copyright 2020 Cloudbase Solutions Srl
# Copyright 2019 ruilopes.com
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

"""Config options available for the VMware metadata service."""

from oslo_config import cfg

from cloudbaseinit.conf import base as conf_base


class VMwareGuestInfoConfigOptions(conf_base.Options):

    """Config options available for the VMware GuestInfo metadata service."""

    def __init__(self, config):
        super(VMwareGuestInfoConfigOptions, self).__init__(
            config, group="vmwareguestinfo")
        self._options = [
            cfg.StrOpt(
                'vmware_rpctool_path',
                default="%ProgramFiles%/VMware/VMware Tools/rpctool.exe",
                help='The local path where VMware rpctool is found')
        ]

    def register(self):
        """Register the current options to the global ConfigOpts object."""
        group = cfg.OptGroup(self.group_name,
                             title='VMware GuestInfo Options')
        self._config.register_group(group)
        self._config.register_opts(self._options, group=group)

    def list(self):
        """Return a list which contains all the available options."""
        return self._options
