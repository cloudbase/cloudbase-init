# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis Inc.
# All Rights Reserved.
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

import glob
import imp
import os
import sys
import traceback

from cloudbaseinit.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def load_from_file(filepath, parent_set):
    class_inst = None

    mod_name, file_ext = os.path.splitext(os.path.split(filepath)[-1])

    if file_ext.lower() == '.py':
        py_mod = imp.load_source(mod_name, filepath)

    elif file_ext.lower() == '.pyc':
        py_mod = imp.load_compiled(mod_name, filepath)

    if hasattr(py_mod, "get_plugin"):
        clb = getattr(__import__(mod_name), "get_plugin")
        class_inst = clb(parent_set)

    return class_inst


class PluginSet:

    def __init__(self, path):
        self.path = path
        sys.path.append(self.path)
        self.set = {}
        self.has_custom_handlers = False
        self.custom_handlers = {}

    def get_plugin(self, content_type, file_name):
        pass

    def load(self):
        files = glob.glob(self.path + '/*.py')

        if len(files) == 0:
            LOG.debug("No user data plug-ins found in %s:", self.path)
            return

        for f in files:
            LOG.debug("Trying to load user data plug-in from file: %s", f)
            try:
                plugin = load_from_file(f, self)
                if plugin is not None:
                    LOG.info("Plugin '%s' loaded.", plugin.name)
                    self.set[plugin.type] = plugin
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                LOG.error('Can`t load plugin from the file %s. Skip it.', f)
                LOG.debug(repr(traceback.format_exception(exc_type, exc_value,
                                                          exc_traceback)))

    def reload(self):
        self.set = {}
        self.load()
