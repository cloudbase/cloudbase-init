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

from oslo_log import log as oslo_logging
from six.moves.urllib import error

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice as baseos
from cloudbaseinit.utils import network

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class HttpService(base.BaseHTTPMetadataService, baseos.BaseOpenStackService):
    _POST_PASSWORD_MD_VER = '2013-04-04'

    def __init__(self):
        super(HttpService, self).__init__(
            base_url=CONF.openstack.metadata_base_url,
            https_allow_insecure=CONF.openstack.https_allow_insecure,
            https_ca_bundle=CONF.openstack.https_ca_bundle)
        self._enable_retry = True

    def load(self):
        super(HttpService, self).load()
        if CONF.openstack.add_metadata_private_ip_route:
            network.check_metadata_ip_route(CONF.openstack.metadata_base_url)

        try:
            self._get_meta_data()
            return True
        except Exception:
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.openstack.metadata_base_url)
            return False

    def _post_data(self, path, data):
        self._http_request(path, data=data)
        return True

    def _get_password_path(self):
        return 'openstack/%s/password' % self._POST_PASSWORD_MD_VER

    @property
    def can_post_password(self):
        try:
            self._get_meta_data(self._POST_PASSWORD_MD_VER)
            return True
        except base.NotExistingMetadataException:
            return False

    @property
    def is_password_set(self):
        path = self._get_password_path()
        return len(self._get_data(path)) > 0

    def post_password(self, enc_password_b64):
        try:
            path = self._get_password_path()
            action = lambda: self._post_data(path, enc_password_b64)
            return self._exec_with_retry(action)
        except error.HTTPError as ex:
            if ex.code == 409:
                # Password already set
                return False
            else:
                raise
