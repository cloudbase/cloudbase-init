# Copyright 2012 Cloudbase Solutions Srl
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

PLUGIN_EXECUTION_DONE = 1
PLUGIN_EXECUTE_ON_NEXT_BOOT = 2


class BasePlugin(object):

    def get_name(self):
        return self.__class__.__name__

    def get_os_requirements(self):
        return (None, None)

    def execute(self, service, shared_data):
        pass
