# Copyright 2014 Cloudbase Solutions Srl
# Copyright 2012 Mirantis Inc.
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

from oslo.config import cfg

from cloudbaseinit.metadata.services import base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.utils import network

opts = [
    cfg.StrOpt('ec2_metadata_base_url',
               default='http://169.254.169.254/',
               help='The base URL where the service looks for metadata'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class EC2Service(base.BaseMetadataService):
    _metadata_version = '2009-04-04'

    def __init__(self):
        super(EC2Service, self).__init__()
        self._enable_retry = True

    def load(self):
        super(EC2Service, self).load()
        network.check_metadata_ip_route(CONF.ec2_metadata_base_url)

        try:
            self.get_host_name()
            return True
        except Exception, ex:
            LOG.exception(ex)
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.ec2_metadata_base_url)
            return False

    def _get_response(self, req):
        try:
            return urllib2.urlopen(req)
        except urllib2.HTTPError as ex:
            if ex.code == 404:
                raise base.NotExistingMetadataException()
            else:
                raise

    def _get_data(self, path):
        norm_path = posixpath.join(CONF.ec2_metadata_base_url, path)

        LOG.debug('Getting metadata from: %(norm_path)s',
                  {'norm_path': norm_path})
        req = urllib2.Request(norm_path)
        response = self._get_response(req)
        return response.read()

    def get_host_name(self):
        return self._get_cache_data('%s/meta-data/local-hostname' %
                                    self._metadata_version)

    def get_instance_id(self):
        return self._get_cache_data('%s/meta-data/instance-id' %
                                    self._metadata_version)

    def get_public_keys(self):
        ssh_keys = []

        keys_info = self._get_cache_data(
            '%s/meta-data/public-keys' %
            self._metadata_version).split("\n")

        for key_info in keys_info:
            (idx, key_name) = key_info.split('=')

            ssh_key = self._get_cache_data(
                '%(version)s/meta-data/public-keys/%(idx)s/openssh-key' %
                {'version': self._metadata_version, 'idx': idx})
            ssh_keys.append(ssh_key)

        return ssh_keys

    def get_network_config(self):
        # TODO(alexpilotti): add static network support
        pass
