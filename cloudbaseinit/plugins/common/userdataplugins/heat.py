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

import os

import six

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common.userdataplugins import base
from cloudbaseinit.plugins.common import userdatautils
from cloudbaseinit.utils import encoding

CONF = cloudbaseinit_conf.CONF


class HeatPlugin(base.BaseUserDataPlugin):
    _heat_user_data_filename = "cfn-userdata"

    def __init__(self):
        super(HeatPlugin, self).__init__("text/x-cfninitdata")

    def _check_dir(self, file_name):
        dir_name = os.path.dirname(file_name)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)

    def process(self, part):
        file_name = os.path.join(CONF.heat_config_dir, part.get_filename())
        self._check_dir(file_name)

        payload = part.get_payload(decode=True)
        encoding.write_file(file_name, payload)

        if part.get_filename() == self._heat_user_data_filename:
            # Normalize the payload to bytes, since `execute_user_data_script`
            # operates on bytes and `get_payload` returns a string on
            # Python 3.
            if isinstance(payload, six.text_type):
                payload = payload.encode()
            return userdatautils.execute_user_data_script(payload)
