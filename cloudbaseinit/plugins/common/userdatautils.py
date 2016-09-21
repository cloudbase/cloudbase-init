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

import collections
import os
import re

from oslo_log import log as oslo_logging

from cloudbaseinit.plugins.common import execcmd


LOG = oslo_logging.getLogger(__name__)

_Script = collections.namedtuple('Script', ['extension', 'script_type',
                                            'executor'])
_SCRIPTS = (
    _Script(extension='cmd', executor=execcmd.Shell,
            script_type=re.compile(br'^rem\s+cmd\s')),
    _Script(script_type=re.compile(br'^#!\s*/usr/bin/env\s+python\s'),
            extension='py', executor=execcmd.Python),
    _Script(extension='exe', script_type=None, executor=execcmd.Shell),
    _Script(extension='sh', script_type=re.compile(br'^#!'),
            executor=execcmd.Bash),
    _Script(extension='ps1', executor=execcmd.PowershellSysnative,
            script_type=re.compile(br'^#(ps1|ps1_sysnative)\s')),
    _Script(extension=None, executor=execcmd.Powershell,
            script_type=re.compile(br'^#ps1_x86\s')),
    _Script(extension=None, executor=execcmd.EC2Config,
            script_type=re.compile(br'</?(script|powershell)>')))


def _get_command(data, is_path=False):
    """Returns a specific command executor if the data type is found.

    :param data: It can be either a file or content of user_data type.
    :param is_path: Determines whether :data: is a file path or it
                    contains the user_data content.
    :rtype: An `execcmd` command type or `None`.
    .. note :: In case the data doesn't have a valid extension or
               header, it will return `None`.
    """
    if is_path:
        extension = os.path.splitext(data)[1][1:].lower()
        for script in _SCRIPTS:
            if extension == script.extension:
                return script.executor(data)
        with open(data, 'rb') as file_handler:
            file_handler.seek(0)
            user_data = file_handler.read()
    else:
        user_data = data

    for script in _SCRIPTS:
        if script.script_type and script.script_type.search(user_data):
            return script.executor.from_data(user_data)
    return None


def get_command(data):
    return _get_command(data)


def get_command_from_path(path):
    return _get_command(path, is_path=True)


def execute_user_data_script(user_data):
    ret_val = 0
    out = err = None
    command = get_command(user_data)
    if not command:
        LOG.warning('Unsupported user_data format')
        return ret_val

    try:
        out, err, ret_val = command.execute()
    except Exception as exc:
        LOG.warning('An error occurred during user_data execution: \'%s\'',
                    exc)
    else:
        LOG.debug('User_data stdout:\n%s', out)
        LOG.debug('User_data stderr:\n%s', err)

    LOG.info('User_data script ended with return code: %d', ret_val)
    return ret_val
