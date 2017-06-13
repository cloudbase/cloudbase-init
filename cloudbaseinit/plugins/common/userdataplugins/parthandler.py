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
import tempfile

from cloudbaseinit.plugins.common.userdataplugins import base
from cloudbaseinit.utils import classloader
from cloudbaseinit.utils import encoding


class PartHandlerPlugin(base.BaseUserDataPlugin):

    def __init__(self):
        super(PartHandlerPlugin, self).__init__("text/part-handler")

    def process(self, part):
        temp_dir = tempfile.gettempdir()
        part_handler_path = os.path.join(temp_dir, part.get_filename())
        encoding.write_file(part_handler_path, part.get_payload(decode=True))

        part_handler = classloader.ClassLoader().load_module(part_handler_path)

        if (part_handler and
                hasattr(part_handler, "list_types") and
                hasattr(part_handler, "handle_part")):
            part_handlers_dict = {}
            for handled_type in part_handler.list_types():
                part_handlers_dict[handled_type] = part_handler.handle_part
            return part_handlers_dict
