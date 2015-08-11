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


import functools
import re

from oslo_log import log as oslo_logging

from cloudbaseinit.plugins.common import execcmd


LOG = oslo_logging.getLogger(__name__)

# Avoid 80+ length by using a local variable, which
# is deleted afterwards.
_compile = functools.partial(re.compile, flags=re.I)
FORMATS = (
    (_compile(br'^rem\s+cmd\s'), execcmd.Shell),
    (_compile(br'^#!\s*/usr/bin/env\s+python\s'), execcmd.Python),
    (_compile(br'^#!'), execcmd.Bash),
    (_compile(br'^#(ps1|ps1_sysnative)\s'), execcmd.PowershellSysnative),
    (_compile(br'^#ps1_x86\s'), execcmd.Powershell),
    (_compile(br'</?(script|powershell)>'), execcmd.EC2Config),
)
del _compile


def _get_command(data):
    # Get the command which should process the given data.
    for pattern, command_class in FORMATS:
        if pattern.search(data):
            return command_class.from_data(data)


def execute_user_data_script(user_data):
    ret_val = 0
    out = err = None
    command = _get_command(user_data)
    if not command:
        LOG.warning('Unsupported user_data format')
        return ret_val

    try:
        out, err, ret_val = command()
    except Exception as exc:
        LOG.warning('An error occurred during user_data execution: \'%s\'',
                    exc)
    else:
        LOG.debug('User_data stdout:\n%s', out)
        LOG.debug('User_data stderr:\n%s', err)

    LOG.info('User_data script ended with return code: %d', ret_val)
    return ret_val
