# Copyright 2013 Mirantis Inc.
# Copyright 2014 Cloudbase Solutions Srl
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

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.plugins.windows.userdataplugins import base
from cloudbaseinit.plugins.windows import userdatautils

LOG = logging.getLogger(__name__)


class HeatPlugin(base.BaseUserDataPlugin):
    _heat_user_data_filename = "cfn-userdata"

    def __init__(self):
        super(HeatPlugin, self).__init__("text/x-cfninitdata")

    def process(self, part):
        # Only user-data part of Heat multipart data is supported.
        # All other cfinitdata part will be skipped
        if part.get_filename() == self._heat_user_data_filename:
            userdatautils.execute_user_data_script(part.get_payload())
