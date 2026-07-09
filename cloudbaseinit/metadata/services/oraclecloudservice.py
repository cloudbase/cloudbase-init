# Copyright (c) 2026, Oracle and/or its affiliates.
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

from base64 import b64decode

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import network

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class OracleCloudService(base.BaseHTTPMetadataService):
    _metadata_version = 'v2'
    _headers = {"Authorization": "Bearer Oracle"}

    def __init__(self):
        super(OracleCloudService, self).__init__(
            base_url=CONF.oraclecloud.metadata_base_url,
            https_allow_insecure=CONF.oraclecloud.https_allow_insecure,
            https_ca_bundle=CONF.oraclecloud.https_ca_bundle)
        self._enable_retry = True

    def _http_request(self, url, data=None, headers=None, method=None):
        headers = dict(headers or {})
        headers.update(self._headers)

        return super(OracleCloudService, self)._http_request(
            url, data, headers, method)

    def load(self):
        super(OracleCloudService, self).load()
        if CONF.oraclecloud.add_metadata_private_ip_route:
            network.check_metadata_ip_route(CONF.oraclecloud.metadata_base_url)

        try:
            self.get_instance_id()
            return True
        except Exception as ex:
            LOG.exception(ex)
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.oraclecloud.metadata_base_url)
            return False

    def get_instance_id(self):
        return self._get_cache_data('opc/%s/instance/id' %
                                    self._metadata_version, decode=True)

    def get_user_data(self):
        return b64decode(self._get_cache_data(
            'opc/%s/instance/metadata/user_data' % self._metadata_version))

    def get_host_name(self):
        return self._get_cache_data('opc/%s/instance/hostname' %
                                    self._metadata_version, decode=True)
