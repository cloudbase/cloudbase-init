# Copyright 2020 Cloudbase Solutions Srl
# Copyright 2019 ruilopes.com
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
import gzip
import io
import os

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import serialization

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class VMwareGuestInfoService(base.BaseMetadataService):
    def __init__(self):
        super(VMwareGuestInfoService, self).__init__()
        self._rpc_tool_path = None
        self._osutils = osutils_factory.get_os_utils()
        self._meta_data = {}
        self._user_data = None

    @staticmethod
    def _decode_data(raw_data, is_base64, is_gzip):
        """Decode raw_data from base64 / ungzip"""
        if not raw_data:
            return

        if is_base64:
            raw_data = base64.b64decode(raw_data)

        if is_gzip:
            with gzip.GzipFile(fileobj=io.BytesIO(raw_data), mode='rb') as dt:
                raw_data = dt.read()

        return raw_data

    def _get_guestinfo_value(self, key):
        rpc_command = 'info-get guestinfo.%s' % key
        data, stderr, exit_code = self._osutils.execute_process([
            self._rpc_tool_path,
            rpc_command
        ])
        if exit_code:
            LOG.debug(
                'Failed to execute "%(rpctool_path)s \'%(rpc_command)s\'" '
                'with exit code: %(exit_code)s\nstdout: '
                '%(stdout)s\nstderr: %(stderr)s' % {
                    'rpctool_path': self._rpc_tool_path,
                    'rpc_command': rpc_command, 'exit_code': exit_code,
                    'stdout': data, 'stderr': stderr})
            return

        return data

    def _get_guest_data(self, key):
        is_base64 = False
        is_gzip = False
        encoding_plain_text = 'plaintext'
        raw_data = self._get_guestinfo_value(key)
        raw_encoding = self._get_guestinfo_value("%s.encoding" % key)

        if not raw_encoding or not raw_encoding.strip():
            raw_encoding = encoding_plain_text

        encoding = raw_encoding.strip()
        if isinstance(encoding, bytes):
            encoding = encoding.decode("utf-8")

        if encoding in ('gzip+base64', 'gz+b64'):
            is_gzip = True
            is_base64 = True
        elif encoding in ('base64', 'b64'):
            is_base64 = True
        elif encoding != encoding_plain_text:
            raise exception.CloudbaseInitException(
                "Encoding %s not supported" % encoding)

        LOG.debug("Decoding key %s: encoding %s", key, encoding)
        return self._decode_data(raw_data, is_base64, is_gzip)

    def load(self):
        super(VMwareGuestInfoService, self).load()

        if not CONF.vmwareguestinfo.vmware_rpctool_path:
            LOG.info("rpctool_path is empty. "
                     "Please provide a value for VMware rpctool path.")
            return False

        self._rpc_tool_path = os.path.abspath(
            os.path.expandvars(CONF.vmwareguestinfo.vmware_rpctool_path))

        if not os.path.exists(self._rpc_tool_path):
            LOG.info("%s does not exist. "
                     "Please provide a valid value for VMware rpctool path."
                     % self._rpc_tool_path)
            return False

        self._meta_data = serialization.parse_json_yaml(
            self._get_guest_data('metadata'))
        if not isinstance(self._meta_data, dict):
            LOG.warning("Instance metadata is not a dictionary.")
            self._meta_data = {}

        self._user_data = self._get_guest_data('userdata')

        if self._meta_data or self._user_data:
            return True

    def _get_data(self, path):
        pass

    def get_instance_id(self):
        return self._meta_data.get('instance-id')

    def get_user_data(self):
        return self._user_data

    def get_host_name(self):
        return self._meta_data.get('local-hostname')

    def get_public_keys(self):
        public_keys = []
        public_keys_data = self._meta_data.get('public-keys-data')

        if public_keys_data:
            public_keys = public_keys_data.splitlines()

        return list(set((key.strip() for key in public_keys)))

    def get_admin_username(self):
        return self._meta_data.get('admin-username')

    def get_admin_password(self):
        return self._meta_data.get('admin-password')
