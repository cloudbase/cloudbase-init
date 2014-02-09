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
import os

from cloudbaseinit.metadata.services import base
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging

opts = [
    cfg.StrOpt('ec2_metadata_base_url',
               default='http://169.254.169.254/2009-04-04/',
               help='The base URL where the service looks for metadata'),
]

ec2nodes = [
    'ami-id', 'ami-launch-index', 'ami-manifest-path', 'ancestor-ami-ids',
    'hostname', 'block-device-mapping', 'kernel-id',
    'placement/availability-zone', 'instance-action', 'instance-id',
    'instance-type', 'product-codes', 'local-hostname', 'local-ipv4',
    'public-hostname', 'public-ipv4', 'ramdisk-id', 'reservation-id',
    'security-groups', 'public-keys/', 'public-keys/0/',
    'public-keys/0/openssh-key', 'admin_pass']

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class EC2Service(base.BaseMetadataService):
    def __init__(self):
        super(EC2Service, self).__init__()
        self._enable_retry = True
        self.error_count = 0

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
        data = {}
        LOG.debug("Check for EC2 interface availability...")
        if not self._check_EC2():
            raise Exception("EC2 interface is not available")

        LOG.debug('Getting data for the path: %s' % path)
        if path.endswith('meta_data.json'):
            for key in ec2nodes:
                LOG.debug('Getting metadata from: %s' % key)
                try:
                    data[key] = self._get_EC2_value(key)
                except:
                    LOG.info("EC2 value %s is not available. Skip it." % key)
            # Saving keys to the local folder
            self._load_public_keys(data)

        if path.endswith('user_data'):
            norm_path = posixpath.join(CONF.ec2_metadata_base_url, 'user-data')
            LOG.debug('Getting metadata from: %(norm_path)s' % locals())
            try:
                req = urllib2.Request(norm_path)
                response = urllib2.urlopen(req)
                data = response.read()
                LOG.debug("Got data: %s" % data)
            except:
                LOG.error("EC2 user-data is not available.")
        return data

    def _check_EC2(self):
        try:
            data = self._get_EC2_value('')
            return True
        except:
            return False

    def _get_EC2_value(self, key):
        meta_path = posixpath.join(
            CONF.ec2_metadata_base_url, 'meta-data', key)
        req = urllib2.Request(meta_path)
        response = urllib2.urlopen(req)
        return response.read()

    def _load_public_keys(self, data):
        try:
            key_list = self._get_EC2_value('public-keys/')
            LOG.debug("Got a list of keys %s" % key_list)
            data['public_keys'] = {}

            for key_name in key_list.split('\n'):
                key_index = key_name.split('=')[0]
                LOG.debug('Loading key %s' % key_index)
                key = self._get_EC2_value(
                    'public-keys/%s/openssh-key' % key_index)
                data['public_keys'].update({key_index: key})

        except Exception, ex:
            LOG.debug("Can't save public key %s" % ex)
            LOG.debug(traceback.format_exc())
