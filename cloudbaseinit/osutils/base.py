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

import base64
import os
import subprocess


class BaseOSUtils(object):
    def reboot(self):
        pass

    def user_exists(self, username):
        pass

    def generate_random_password(self, length):
        # On Windows os.urandom() uses CryptGenRandom, which is a
        # cryptographically secure pseudorandom number generator
        b64_password = base64.b64encode(os.urandom(256))
        return b64_password.replace('/', '').replace('+', '')[:length]

    def execute_process(self, args, shell=True):
        p = subprocess.Popen(args,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=shell)
        (out, err) = p.communicate()
        return (out, err, p.returncode)

    def sanitize_shell_input(self, value):
        pass

    def create_user(self, username, password, password_expires=False):
        pass

    def set_user_password(self, username, password, password_expires=False):
        pass

    def add_user_to_local_group(self, username, groupname):
        pass

    def set_host_name(self, new_host_name):
        pass

    def get_user_home(self, username):
        pass

    def get_network_adapters(self):
        pass

    def set_static_network_config(self, adapter_name, address, netmask,
                                  broadcast, gateway, dnsdomain,
                                  dnsnameservers):
        pass

    def set_config_value(self, name, value, section=None):
        pass

    def get_config_value(self, name, section=None):
        pass

    def wait_for_boot_completion(self):
        pass

    def terminate(self):
        pass

    def get_default_gateway(self):
        pass

    def check_static_route_exists(self, destination):
        pass

    def add_static_route(self, destination, mask, next_hop, interface_index,
                         metric):
        pass

    def check_os_version(self, major, minor, build=0):
        pass

    def get_volume_label(self, drive):
        pass
