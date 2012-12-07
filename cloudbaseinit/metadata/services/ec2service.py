# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
import traceback

from cloudbaseinit.metadata.services.base import *
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging

opts = [
    cfg.StrOpt('ec2_metadata_base_url', default='http://169.254.169.254/2009-04-04/',
        help='The base URL where the service looks for metadata'),
  ]

ec2nodes = ['ami-id','ami-launch-index','ami-manifest-path','hostname',
'instance-action','instance-id','instance-type',
'local-hostname','local-ipv4','public-hostname','public-ipv4']

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

class EC2Service(BaseMetadataService):
    def load(self):
        super(EC2Service, self).load()
        try:
            self.get_meta_data('openstack')
            return True
        except Exception, err:
            LOG.debug(err)
            LOG.debug(traceback.format_exc())          
            LOG.debug('Metadata not found at URL \'%s\'' %
                CONF.ec2_metadata_base_url)
            return False

    def _get_data(self, path):
        data={}
        LOG.debug('Getting data for the path: %s' % path)
        if path.endswith('meta_data.json'):
         meta_path=posixpath.join(CONF.ec2_metadata_base_url, 'meta-data')
         for key in ec2nodes:
           norm_path = posixpath.join(meta_path, key)
           LOG.debug('Getting metadata from: %(norm_path)s' % locals())
           req = urllib2.Request(norm_path)
           response = urllib2.urlopen(req)
           data[key]=response.read()
        
        if path.endswith('user_data'):
           norm_path = posixpath.join(CONF.ec2_metadata_base_url, 'user-data')
           LOG.debug('Getting metadata from: %(norm_path)s' % locals())
           req = urllib2.Request(norm_path)
           response = urllib2.urlopen(req)
           data=response.read()
        return data
