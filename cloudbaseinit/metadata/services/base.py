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

import json
import logging
import os
import posixpath

LOG = logging.getLogger(__name__)


class BaseMetadataService(object):
    def load(self):
        self._cache = {}

    def _get_data(self, path):
        pass

    def _get_cache_data(self, path):
        if path in self._cache:
            LOG.debug('Using cached copy of metadata: \'%s\'' % path)
            return self._cache[path]
        else:
            data = self._get_data(path)
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
        return json.loads(self._get_cache_data(path))

    def cleanup(self):
        pass
