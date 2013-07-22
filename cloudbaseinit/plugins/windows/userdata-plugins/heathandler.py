# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis Inc.
# All Rights Reserved.
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

import re
import tempfile
import uuid
import email
import tempfile
import os
import errno
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils.factory import *
from cloudbaseinit.plugins.windows.userdata import handle

LOG = logging.getLogger("cloudbaseinit")

def get_plugin(parent_set):
    return HeatUserDataHandler(parent_set)

class HeatUserDataHandler:

    def __init__(self, parent_set):
        LOG.info("Heat user data part handler is loaded.")
        self.type = "text/x-cfninitdata"
        self.name = "Heat userdata plugin"
        return

    def process(self, part):
        #Only user-data part of Heat multipart data is supported. All other cfinitdata part will be skipped
        if part.get_filename() == "cfn-userdata":
            handle(part.get_payload())
        return
 
