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

import posixpath
import time

from oauth import oauth
from oslo.config import cfg
from six.moves.urllib import error
from six.moves.urllib import request

from cloudbaseinit.metadata.services import base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.utils import x509constants

opts = [
    cfg.StrOpt('maas_metadata_url', default=None,
               help='The base URL for MaaS metadata'),
    cfg.StrOpt('maas_oauth_consumer_key', default="",
               help='The MaaS OAuth consumer key'),
    cfg.StrOpt('maas_oauth_consumer_secret', default="",
               help='The MaaS OAuth consumer secret'),
    cfg.StrOpt('maas_oauth_token_key', default="",
               help='The MaaS OAuth token key'),
    cfg.StrOpt('maas_oauth_token_secret', default="",
               help='The MaaS OAuth token secret'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class MaaSHttpService(base.BaseMetadataService):
    _METADATA_2012_03_01 = '2012-03-01'

    def __init__(self):
        super(MaaSHttpService, self).__init__()
        self._enable_retry = True
        self._metadata_version = self._METADATA_2012_03_01

    def load(self):
        super(MaaSHttpService, self).load()

        if not CONF.maas_metadata_url:
            LOG.debug('MaaS metadata url not set')
        else:
            try:
                self._get_cache_data('%s/meta-data/' % self._metadata_version)
                return True
            except Exception as ex:
                LOG.exception(ex)
                LOG.debug('Metadata not found at URL \'%s\'' %
                          CONF.maas_metadata_url)
        return False

    def _ensure_network_up(self, request):
        while True:
            try:
                response = request.urlopen(request)
                return response
            except socket.error:
                LOG.debug("socket error while trying to get a response, network most likely down.")
                pass
            except Exception as e:
                raise e

    def _get_response(req):
        try:
            return self._ensure_network_up(req)
        except error.HTTPError as ex:
            if ex.code == 404:
                raise base.NotExistingMetadataException()
            else:
                raise

    def _get_oauth_headers(self, url):
        consumer = oauth.OAuthConsumer(CONF.maas_oauth_consumer_key,
                                       CONF.maas_oauth_consumer_secret)
        token = oauth.OAuthToken(CONF.maas_oauth_token_key,
                                 CONF.maas_oauth_token_secret)

        parameters = {'oauth_version': "1.0",
                      'oauth_nonce': oauth.generate_nonce(),
                      'oauth_timestamp': int(time.time()),
                      'oauth_token': token.key,
                      'oauth_consumer_key': consumer.key}

        req = oauth.OAuthRequest(http_url=url, parameters=parameters)
        req.sign_request(oauth.OAuthSignatureMethod_PLAINTEXT(), consumer,
                         token)

        return req.to_header()

    def _get_data(self, path):
        norm_path = posixpath.join(CONF.maas_metadata_url, path)
        oauth_headers = self._get_oauth_headers(norm_path)

        LOG.debug('Getting metadata from: %(norm_path)s',
                  {'norm_path': norm_path})
        req = request.Request(norm_path, headers=oauth_headers)
        response = self._get_response(req)
        return response.read()

    def get_host_name(self):
        return self._get_cache_data('%s/meta-data/local-hostname' %
                                    self._metadata_version)

    def get_instance_id(self):
        return self._get_cache_data('%s/meta-data/instance-id' %
                                    self._metadata_version)

    def _get_list_from_text(self, text, delimiter):
        return [v + delimiter for v in text.split(delimiter)]

    def get_public_keys(self):
        return self._get_list_from_text(
            self._get_cache_data('%s/meta-data/public-keys' %
                                 self._metadata_version), "\n")

    def get_client_auth_certs(self):
        return self._get_list_from_text(
            self._get_cache_data('%s/meta-data/x509' % self._metadata_version),
            "%s\n" % x509constants.PEM_FOOTER)

    def get_user_data(self):
        return self._get_cache_data('%s/user-data' % self._metadata_version)
