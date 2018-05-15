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

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import network

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class Foreman(base.BaseHTTPMetadataService):

    def __init__(self):
        super(Foreman, self).__init__(
            base_url=CONF.foreman.metadata_base_url,
            https_allow_insecure=CONF.foreman.https_allow_insecure,
            https_ca_bundle=CONF.foreman.https_ca_bundle)
        self._enable_retry = True

    def load(self):
        super(Foreman, self).load()

        try:
            self.get_user_data()
            return True
        except Exception as ex:
            LOG.exception(ex)
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.foreman.metadata_base_url)
            return False

    def get_user_data(self):
        return self._get_cache_data('userdata/user-data')
