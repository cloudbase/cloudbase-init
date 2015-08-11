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

import imp
import os

from oslo_log import log as oslo_logging


LOG = oslo_logging.getLogger(__name__)


class ClassLoader(object):

    def load_class(self, class_path):
        LOG.debug('Loading class \'%s\'' % class_path)
        parts = class_path.rsplit('.', 1)
        module = __import__(parts[0], fromlist=parts[1])
        return getattr(module, parts[1])

    def load_module(self, path):
        module_name, file_ext = os.path.splitext(os.path.split(path)[-1])

        if file_ext.lower() == '.py':
            module = imp.load_source(module_name, path)
        elif file_ext.lower() == '.pyc':
            module = imp.load_compiled(module_name, path)

        return module
