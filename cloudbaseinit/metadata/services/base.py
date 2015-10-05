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
import gzip
import io
import time

from oslo_config import cfg
from oslo_log import log as oslo_logging
import six

from cloudbaseinit.utils import encoding


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

LOG = oslo_logging.getLogger(__name__)

# Both the custom service(s) and the networking plugin
# should know about the entries of these kind of objects.
NetworkDetails = collections.namedtuple(
    "NetworkDetails",
    [
        "name",
        "mac",
        "address",
        "address6",
        "netmask",
        "netmask6",
        "broadcast",
        "gateway",
        "gateway6",
        "dnsnameservers",
    ]
)


class NotExistingMetadataException(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class BaseMetadataService(object):
    _GZIP_MAGIC_NUMBER = b'\x1f\x8b'

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

    def _get_cache_data(self, path, decode=False):
        """Get meta data with caching and decoding support."""
        key = (path, decode)
        if key in self._cache:
            LOG.debug("Using cached copy of metadata: '%s'" % path)
            return self._cache[key]
        else:
            data = self._exec_with_retry(lambda: self._get_data(path))
            if decode:
                data = encoding.get_as_string(data)
            self._cache[key] = data
            return data

    def get_instance_id(self):
        pass

    def get_content(self, name):
        """Get raw content within a service."""

    def get_user_data(self):
        pass

    def get_decoded_user_data(self):
        """Get the decoded user data, if any

        The user data can be gzip-encoded, which means
        that every access to it should verify this fact,
        leading to code duplication.
        """
        user_data = self.get_user_data()
        if user_data and user_data[:2] == self._GZIP_MAGIC_NUMBER:
            bio = io.BytesIO(user_data)
            with gzip.GzipFile(fileobj=bio, mode='rb') as out:
                user_data = out.read()

        return user_data

    def get_host_name(self):
        pass

    def get_public_keys(self):
        """Get a list of space-stripped strings as public keys."""
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

    @property
    def can_update_password(self):
        """The ability to update password of the metadata provider.

        If :meth:`~can_update_password` is True, plugins can check
        periodically (e.g. at every boot) if the password changed.

        :rtype: bool

        .. notes:
            The password will be updated only if the
            :meth:`~is_password_changed` returns True.
        """
        return False

    def is_password_changed(self):
        """Check if the metadata provider has a new password for this instance

        :rtype: bool

        .. notes:
            This method will be used only when :meth:`~can_update_password`
            is True.
        """
        return False
