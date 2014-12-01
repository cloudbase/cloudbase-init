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


import json
import posixpath

from oslo.config import cfg

from cloudbaseinit.metadata.services import base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import x509constants


opts = [
    cfg.StrOpt('metadata_base_url', default='http://169.254.169.254/',
               help='The base URL where the service looks for metadata'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class BaseOpenStackService(base.BaseMetadataService):

    def get_content(self, name):
        path = posixpath.normpath(
            posixpath.join('openstack', 'content', name))
        return self._get_cache_data(path)

    def get_user_data(self):
        path = posixpath.normpath(
            posixpath.join('openstack', 'latest', 'user_data'))
        return self._get_cache_data(path)

    def _get_meta_data(self, version='latest'):
        path = posixpath.normpath(
            posixpath.join('openstack', version, 'meta_data.json'))
        data = self._get_cache_data(path)
        if data:
            return json.loads(encoding.get_as_string(data))

    def get_instance_id(self):
        return self._get_meta_data().get('uuid')

    def get_host_name(self):
        return self._get_meta_data().get('hostname')

    def get_public_keys(self):
        public_keys = self._get_meta_data().get('public_keys')
        if public_keys:
            return public_keys.values()

    def get_network_details(self):
        network_config = self._get_meta_data().get('network_config')
        if not network_config:
            return None
        key = "content_path"
        if key not in network_config:
            return None

        content_name = network_config[key].rsplit("/", 1)[-1]
        content = self.get_content(content_name)
        content = encoding.get_as_string(content)

        return debiface.parse(content)

    def get_admin_password(self):
        meta_data = self._get_meta_data()
        meta = meta_data.get('meta')

        if meta and 'admin_pass' in meta:
            password = meta['admin_pass']
        elif 'admin_pass' in meta_data:
            password = meta_data['admin_pass']
        else:
            password = None

        return password

    def get_client_auth_certs(self):
        cert_data = None

        meta_data = self._get_meta_data()
        meta = meta_data.get('meta')

        if meta:
            i = 0
            while True:
                # Chunking is necessary as metadata items can be
                # max. 255 chars long
                cert_chunk = meta.get('admin_cert%d' % i)
                if not cert_chunk:
                    break
                if not cert_data:
                    cert_data = cert_chunk
                else:
                    cert_data += cert_chunk
                i += 1

        if not cert_data:

            # Look if the user_data contains a PEM certificate
            try:
                user_data = self.get_user_data()
                if user_data.startswith(
                        x509constants.PEM_HEADER.encode()):
                    cert_data = user_data
            except base.NotExistingMetadataException:
                LOG.debug("user_data metadata not present")

        if cert_data:
            return [cert_data]
