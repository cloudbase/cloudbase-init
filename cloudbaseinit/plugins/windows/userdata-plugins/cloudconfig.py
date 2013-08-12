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
from cloudbaseinit.openstack.common import log as logging

LOG = logging.getLogger("cloudbaseinit")

def get_plugin(parent_set):
    return CloudConfigHandler(parent_set)
    
class CloudConfigHandler:
    
    def __init__(self, parent_set):
        LOG.info("Cloud-config part handler is loaded.")
        self.type = "text/cloud-config"
        self.name = "Cloud-config userdata plugin"
        return
    
    def process(self, part):
        return
    
