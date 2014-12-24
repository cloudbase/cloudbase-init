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


import abc
import collections
import time

from oslo.config import cfg

from cloudbaseinit.openstack.common import log as logging


opts = [
    cfg.IntOpt('retry_count', default=5,
               help='Max. number of attempts for fetching metadata in '
               'case of transient errors'),
    cfg.FloatOpt('retry_count_interval', default=4,
                 help='Interval between attempts in case of transient errors, '
                 'expressed in seconds'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

# Both the custom service(s) and the networking plugin
# should know about the entries of these kind of objects.
NetworkDetails = collections.namedtuple(
    "NetworkDetails",
    [
        "name",
        "mac",
        "address",
        "netmask",
        "broadcast",
        "gateway",
        "dnsnameservers",
    ]
)


class NotExistingMetadataException(Exception):
    pass


class BaseMetadataService(object):
    def __init__(self):
        self._cache = {}
        self._enable_retry = False

    def get_name(self):
        return self.__class__.__name__

    def load(self):
        self._cache = {}

    @abc.abstractmethod
    def _get_data(self, path):
        pass

    def _exec_with_retry(self, action):
        i = 0
        while True:
            try:
                return action()
            except NotExistingMetadataException:
                raise
            except Exception:
                if self._enable_retry and i < CONF.retry_count:
                    i += 1
                    time.sleep(CONF.retry_count_interval)
                else:
                    raise

    def _get_cache_data(self, path):
        if path in self._cache:
            LOG.debug("Using cached copy of metadata: '%s'" % path)
            return self._cache[path]
        else:
            data = self._exec_with_retry(lambda: self._get_data(path))
            self._cache[path] = data
            return data

    def get_instance_id(self):
        pass

    def get_content(self, name):
        """Get raw content within a service."""

    def get_user_data(self):
        pass

    def get_host_name(self):
        pass

    def get_public_keys(self):
        pass

    def get_network_details(self):
        """Return a list of `NetworkDetails` objects.

        These objects provide details regarding static
        network configuration, details which can be found
        in the namedtuple defined above.
        """

    def get_admin_password(self):
        pass

    @property
    def can_post_password(self):
        return False

    @property
    def is_password_set(self):
        return False

    def post_password(self, enc_password_b64):
        pass

    def get_client_auth_certs(self):
        pass

    def cleanup(self):
        pass
