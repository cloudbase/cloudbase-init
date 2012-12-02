# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import subprocess

class BaseOSUtils(object):
    def reboot(self):
        pass

    def user_exists(self, username):
        pass

    def execute_process(self, args, shell=True):
        p = subprocess.Popen(args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell)
        (out, err) = p.communicate()
        return (out, err, p.returncode)

    def sanitize_shell_input(shell, value):
        pass

    def create_user(self, username, password, password_expires=False):
        pass

    def set_user_password(self, username, password, password_expires=False):
        pass

    def add_user_to_local_group(self, username, groupname):
        pass

    def set_host_name(shell, new_host_name):
        pass

    def get_user_home(self, username):
        pass

    def get_network_adapters(self):
        pass

    def set_static_network_config(self, adapter_name, address, netmask,
        broadcast, gateway, dnsdomain, dnsnameservers):
        pass

    def set_config_value(self, name, value):
        pass

    def get_config_value(self, name):
        pass

