# Copyright 2015 Cloudbase Solutions Srl
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

import os

from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import classloader


def get_storage_manager():
    class_paths = {
        "VDS": "cloudbaseinit.utils.windows.storage.vds_storage_manager."
        "VDSStorageManager",
        "WSM": "cloudbaseinit.utils.windows.storage.wsm_storage_manager."
        "WSMStorageManager",
    }

    osutils = osutils_factory.get_os_utils()
    cl = classloader.ClassLoader()
    if os.name == "nt":
        if osutils.is_nano_server():
            # VDS is not available on Nano Server
            # WSM supersedes VDS since Windows Server 2012 / Windows 8
            return cl.load_class(class_paths["WSM"])()
        else:
            return cl.load_class(class_paths["VDS"])()

    raise NotImplementedError("No storage manager available for this platform")
