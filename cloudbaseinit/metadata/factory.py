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

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.utils import *

opts = [
    cfg.ListOpt('metadata_services', default=[
        'cloudbaseinit.metadata.services.configdrive.configdrive.'
            'ConfigDriveService',
        'cloudbaseinit.metadata.services.httpservice.HttpService',
        ],
        help='List of enabled metadata service classes, '
            'to be tested fro availability in the provided order. '
            'The first available service will be used to retrieve metadata')
  ]

CONF = cfg.CONF
CONF.register_opts(opts)
LOG = logging.getLogger(__name__)


class MetadataServiceFactory(object):
    def get_metadata_service(self):
        # Return the first service that loads correctly
        utils = Utils()
        for class_path in CONF.metadata_services:
            service = utils.load_class(class_path)()
            try:
                if service.load():
                    return service
            except Exception, ex:
                LOG.error('Failed to load metadata service \'%(class_path)s\' '
                    'with error: %(ex)s'%
                    locals())
        raise Exception("No available service found")
