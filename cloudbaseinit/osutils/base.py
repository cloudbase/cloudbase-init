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
import sys


class BaseOSUtils(object):
    PROTOCOL_TCP = "TCP"
    PROTOCOL_UDP = "UDP"

    def reboot(self):
        raise NotImplementedError()

    def user_exists(self, username):
        raise NotImplementedError()

    def generate_random_password(self, length):
        # On Windows os.urandom() uses CryptGenRandom, which is a
        # cryptographically secure pseudorandom number generator
        b64_password = base64.b64encode(os.urandom(256))
        return b64_password.replace(
            b'/', b'').replace(b'+', b'')[:length].decode()

    def execute_process(self, args, shell=True, decode_output=False):
        p = subprocess.Popen(args,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=shell)
        (out, err) = p.communicate()

        if decode_output and sys.version_info < (3, 0):
            out = out.decode(sys.stdout.encoding)
            err = err.decode(sys.stdout.encoding)

        return out, err, p.returncode

    def sanitize_shell_input(self, value):
        raise NotImplementedError()

    def create_user(self, username, password, password_expires=False):
        raise NotImplementedError()

    def set_user_password(self, username, password, password_expires=False):
        raise NotImplementedError()

    def add_user_to_local_group(self, username, groupname):
        raise NotImplementedError()

    def set_host_name(self, new_host_name):
        raise NotImplementedError()

    def get_user_home(self, username):
        raise NotImplementedError()

    def get_network_adapters(self):
        raise NotImplementedError()

    def set_static_network_config(self, mac_address, address, netmask,
                                  broadcast, gateway, dnsnameservers):
        raise NotImplementedError()

    def set_config_value(self, name, value, section=None):
        raise NotImplementedError()

    def get_config_value(self, name, section=None):
        raise NotImplementedError()

    def wait_for_boot_completion(self):
        pass

    def reset_service_password(self):
        return False

    def terminate(self):
        pass

    def get_default_gateway(self):
        raise NotImplementedError()

    def check_static_route_exists(self, destination):
        raise NotImplementedError()

    def add_static_route(self, destination, mask, next_hop, interface_index,
                         metric):
        raise NotImplementedError()

    def check_os_version(self, major, minor, build=0):
        raise NotImplementedError()

    def get_volume_label(self, drive):
        raise NotImplementedError()

    def firewall_create_rule(self, name, port, protocol, allow=True):
        raise NotImplementedError()

    def firewall_remove_rule(self, name, port, protocol, allow=True):
        raise NotImplementedError()

    def get_maximum_password_length(self):
        """Obtain the maximum password length tailored for each OS."""
        raise NotImplementedError()

    def set_timezone(self, timezone):
        """Set the timezone for this instance."""
        raise NotImplementedError()

    def change_password_next_logon(self, username):
        """Force the given user to change his password at the next login."""
        raise NotImplementedError()

    def set_service_credentials(self, service_name, username, password):
        """Set the username and password for a given service."""
        raise NotImplementedError()

    def get_service_username(self, service_name):
        """Retrieve the username under which a service runs."""
        raise NotImplementedError()
