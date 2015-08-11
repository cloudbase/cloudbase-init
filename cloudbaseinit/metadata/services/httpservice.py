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

import posixpath

from oslo_config import cfg
from oslo_log import log as oslo_logging
from six.moves.urllib import error
from six.moves.urllib import request

from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.utils import network

opts = [
    cfg.StrOpt('metadata_base_url', default='http://169.254.169.254/',
               help='The base URL where the service looks for metadata'),
    cfg.BoolOpt('add_metadata_private_ip_route', default=True,
                help='Add a route for the metadata ip address to the gateway'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = oslo_logging.getLogger(__name__)


class HttpService(baseopenstackservice.BaseOpenStackService):
    _POST_PASSWORD_MD_VER = '2013-04-04'

    def __init__(self):
        super(HttpService, self).__init__()
        self._enable_retry = True

    def load(self):
        super(HttpService, self).load()
        if CONF.add_metadata_private_ip_route:
            network.check_metadata_ip_route(CONF.metadata_base_url)

        try:
            self._get_meta_data()
            return True
        except Exception:
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.metadata_base_url)
            return False

    def _get_response(self, req):
        try:
            return request.urlopen(req)
        except error.HTTPError as ex:
            if ex.code == 404:
                raise base.NotExistingMetadataException()
            else:
                raise

    def _get_data(self, path):
        norm_path = posixpath.join(CONF.metadata_base_url, path)
        LOG.debug('Getting metadata from: %s', norm_path)
        req = request.Request(norm_path)
        response = self._get_response(req)
        return response.read()

    def _post_data(self, path, data):
        norm_path = posixpath.join(CONF.metadata_base_url, path)
        LOG.debug('Posting metadata to: %s', norm_path)
        req = request.Request(norm_path, data=data)
        self._get_response(req)
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
