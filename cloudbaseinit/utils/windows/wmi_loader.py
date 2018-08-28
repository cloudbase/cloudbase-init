# Copyright 2018 Cloudbase Solutions Srl
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
import site

from oslo_log import log as oslo_logging

from cloudbaseinit import exception

LOG = oslo_logging.getLogger(__name__)


def wmi():
    try:
        # PyMI depends on the MI API, not available by default on systems older
        # than Windows 8 / Windows Server 2012
        import wmi
        return wmi
    except ImportError:
        LOG.debug("Couldn't load PyMI module, using legacy WMI")

        wmi_path = None
        for packages_path in site.getsitepackages():
            path = os.path.join(packages_path, "wmi.py")
            if os.path.isfile(path):
                wmi_path = path
                break
        if wmi_path is None:
            raise exception.ItemNotFoundException("wmi module not found")

        return imp.load_source("wmi", wmi_path)
