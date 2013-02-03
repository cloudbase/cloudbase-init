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
import urllib
import urllib2

from cloudbaseinit.metadata.services.base import *
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging

opts = [
    cfg.StrOpt('metadata_base_url', default='http://169.254.169.254/',
        help='The base URL where the service looks for metadata'),
  ]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

class HttpService(BaseMetadataService):
    def load(self):
        super(HttpService, self).load()
        try:
            self.get_meta_data('openstack')
            return True
        except:
            LOG.debug('Metadata not found at URL \'%s\'' %
                CONF.metadata_base_url)
            return False

    def _get_response(self, req):
        try:
            return urllib2.urlopen(req)
        except urllib2.HTTPError as ex:
            if ex.code == 404:            
                raise NotExistingMetadataException()
            else:
                raise ex    
            
    def _get_data(self, path):
        norm_path = posixpath.join(CONF.metadata_base_url, path)
        LOG.debug('Getting metadata from: %(norm_path)s' % locals())
        req = urllib2.Request(norm_path)
        response = self._get_response(req)
        return response.read()
    
    def _post_data(self, path, data):
        norm_path = posixpath.join(CONF.metadata_base_url, path)
        LOG.debug('Posting metadata to: %(norm_path)s' % locals())
        req = urllib2.Request(norm_path, data=urllib.urlencode(data))
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
                raise ex
            
        
    