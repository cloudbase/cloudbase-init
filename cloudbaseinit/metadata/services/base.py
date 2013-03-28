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

import abc
import json
import posixpath
import time

from cloudbaseinit.openstack.common import cfg
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


class NotExistingMetadataException(Exception):
    pass


class BaseMetadataService(object):
    def __init__(self):
        self._cache = {}
        self._enable_retry = False

    def load(self):
        self._cache = {}

    @property
    def can_post_password(self):
        return False

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
            except:
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

    def get_content(self, data_type, name):
        path = posixpath.normpath(
            posixpath.join(data_type, 'content', name))
        return self._get_cache_data(path)

    def get_user_data(self, data_type, version='latest'):
        path = posixpath.normpath(
            posixpath.join(data_type, version, 'user_data'))
        return self._get_cache_data(path)

    def get_meta_data(self, data_type, version='latest'):
        path = posixpath.normpath(
            posixpath.join(data_type, version, 'meta_data.json'))
        data = self._get_cache_data(path)
        if type(data) is str:
            return json.loads(self._get_cache_data(path))
        else:
            return data

    def _post_data(self, path, data):
        raise NotExistingMetadataException()

    def post_password(self, enc_password_b64, version='latest'):
        path = posixpath.normpath(posixpath.join('openstack',
                                                 version,
                                                 'password'))
        action = lambda: self._post_data(path, enc_password_b64)
        return self._exec_with_retry(action)

    def cleanup(self):
        pass
