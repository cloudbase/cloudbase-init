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

from oslo_log import log as oslo_logging

from cloudbaseinit.plugins.common import execcmd


LOG = oslo_logging.getLogger(__name__)

FORMATS = {
    "cmd": execcmd.Shell,
    "exe": execcmd.Shell,
    "sh": execcmd.Bash,
    "py": execcmd.Python,
    "ps1": execcmd.PowershellSysnative,
}


def exec_file(file_path):
    ret_val = 0
    ext = os.path.splitext(file_path)[1][1:].lower()
    command = FORMATS.get(ext)
    if not command:
        # Unsupported
        LOG.warning('Unsupported script file type: %s', ext)
        return ret_val

    try:
        out, err, ret_val = command(file_path).execute()
    except Exception as ex:
        LOG.warning('An error occurred during file execution: \'%s\'', ex)
    else:
        LOG.debug('User_data stdout:\n%s', out)
        LOG.debug('User_data stderr:\n%s', err)

    LOG.info('Script "%(file_path)s" ended with exit code: %(ret_val)d',
             {"file_path": file_path, "ret_val": ret_val})
    return ret_val
