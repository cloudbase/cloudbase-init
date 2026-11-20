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

import os
import subprocess

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class SetUserSSHPublicKeysPlugin(base.BasePlugin):

    @staticmethod
    def _write_authorized_keys(authorized_keys_path, public_keys):
        authorized_keys_dir = os.path.dirname(authorized_keys_path)
        if not os.path.exists(authorized_keys_dir):
            os.makedirs(authorized_keys_dir)

        LOG.info("Writing SSH public keys in: %s" % authorized_keys_path)
        with open(authorized_keys_path, 'w') as f:
            for public_key in public_keys:
                # All public keys are space-stripped.
                f.write(public_key + "\n")

    @staticmethod
    def _set_admin_authorized_keys_acl(authorized_keys_path):
        """Set ACL on administrators_authorized_keys per Microsoft docs.

        Only SYSTEM and Administrators should have access.
        """
        try:
            subprocess.check_call([
                "icacls.exe", authorized_keys_path,
                "/inheritance:r",
                "/grant", "Administrators:F",
                "/grant", "SYSTEM:F",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            LOG.exception("Failed to set ACL on %s" % authorized_keys_path)

    def execute(self, service, shared_data):
        public_keys = service.get_public_keys()
        if not public_keys:
            LOG.debug('Public keys not found in metadata')
            return base.PLUGIN_EXECUTION_DONE, False

        username = service.get_admin_username() or CONF.username

        osutils = osutils_factory.get_os_utils()

        # For users in the Administrators group, write keys to
        # C:\ProgramData\ssh\administrators_authorized_keys as per
        # the default OpenSSH sshd_config Match Group directive.
        # This path does not require the user profile to exist.
        if osutils.is_builtin_admin(username):
            programdata = os.environ.get("ProgramData", r"C:\ProgramData")
            admin_keys_path = os.path.join(
                programdata, "ssh", "administrators_authorized_keys")
            self._write_authorized_keys(admin_keys_path, public_keys)
            self._set_admin_authorized_keys_acl(admin_keys_path)
            return base.PLUGIN_EXECUTION_DONE, False

        user_home = osutils.get_user_home(username)
        if not user_home:
            LOG.warning("User profile not found for %r, "
                        "cannot write SSH public keys", username)
            return base.PLUGIN_EXECUTION_DONE, False

        LOG.debug("User home: %s" % user_home)
        authorized_keys_path = os.path.join(
            user_home, '.ssh', 'authorized_keys')
        self._write_authorized_keys(authorized_keys_path, public_keys)

        return base.PLUGIN_EXECUTION_DONE, False
