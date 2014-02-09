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

import posixpath
import urllib2
import urlparse

from cloudbaseinit.metadata.services import base
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory

opts = [
    cfg.StrOpt('metadata_base_url', default='http://169.254.169.254/',
               help='The base URL where the service looks for metadata'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class HttpService(base.BaseMetadataService):
    def __init__(self):
        super(HttpService, self).__init__()
        self._enable_retry = True

    def _check_metadata_ip_route(self):
        '''
        Workaround for: https://bugs.launchpad.net/quantum/+bug/1174657
        '''
        osutils = osutils_factory.OSUtilsFactory().get_os_utils()

        if osutils.check_os_version(6, 0):
            # 169.254.x.x addresses are not getting routed starting from
            # Windows Vista / 2008
            metadata_netloc = urlparse.urlparse(CONF.metadata_base_url).netloc
            metadata_host = metadata_netloc.split(':')[0]

            if metadata_host.startswith("169.254."):
                if not osutils.check_static_route_exists(metadata_host):
                    (interface_index, gateway) = osutils.get_default_gateway()
                    if gateway:
                        try:
                            osutils.add_static_route(metadata_host,
                                                     "255.255.255.255",
                                                     gateway,
                                                     interface_index,
                                                     10)
                        except Exception, ex:
                            # Ignore it
                            LOG.exception(ex)

    def load(self):
        super(HttpService, self).load()

        self._check_metadata_ip_route()

        try:
            self.get_meta_data('openstack')
            return True
        except:
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.metadata_base_url)
            return False

    @property
    def can_post_password(self):
        return True

    def _get_response(self, req):
        try:
            return urllib2.urlopen(req)
        except urllib2.HTTPError as ex:
            if ex.code == 404:
                raise base.NotExistingMetadataException()
            else:
                raise

    def _get_data(self, path):
        norm_path = posixpath.join(CONF.metadata_base_url, path)
        LOG.debug('Getting metadata from: %(norm_path)s' % locals())
        req = urllib2.Request(norm_path)
        response = self._get_response(req)
        return response.read()

    def _post_data(self, path, data):
        norm_path = posixpath.join(CONF.metadata_base_url, path)
        LOG.debug('Posting metadata to: %(norm_path)s' % locals())
        req = urllib2.Request(norm_path, data=data)
        self._get_response(req)
        return True

    def post_password(self, enc_password_b64, version='latest'):
        try:
            return super(HttpService, self).post_password(enc_password_b64,
                                                          version)
        except urllib2.HTTPError as ex:
            if ex.code == 409:
                # Password already set
                return False
            else:
                raise
