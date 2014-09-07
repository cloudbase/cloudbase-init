# Copyright 2014 Cloudbase Solutions Srl
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

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory

LOG = logging.getLogger(__name__)


def exec_file(file_path):
    shell = False
    powershell = False

    ext = os.path.splitext(file_path)[1][1:].lower()

    if ext == "cmd":
        args = [file_path]
        shell = True
    elif ext == "exe":
        args = [file_path]
    elif ext == "sh":
        args = ["bash.exe", file_path]
    elif ext == "py":
        args = ["python.exe", file_path]
    elif ext == "ps1":
        powershell = True
    else:
        # Unsupported
        LOG.warning('Unsupported script file type: %s' % ext)
        return 0

    osutils = osutils_factory.get_os_utils()

    try:
        if powershell:
            (out, err,
             ret_val) = osutils.execute_powershell_script(file_path)
        else:
            (out, err, ret_val) = osutils.execute_process(args, shell)

        LOG.info('Script "%(file_path)s" ended with exit code: %(ret_val)d' %
                 {"file_path": file_path, "ret_val": ret_val})
        LOG.debug('User_data stdout:\n%s' % out)
        LOG.debug('User_data stderr:\n%s' % err)

        return ret_val
    except Exception as ex:
        LOG.warning('An error occurred during file execution: \'%s\'' % ex)
