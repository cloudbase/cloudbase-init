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
import re
import tempfile
import uuid

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory

LOG = logging.getLogger(__name__)


def execute_user_data_script(user_data):
    osutils = osutils_factory.OSUtilsFactory().get_os_utils()

    target_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
    if re.search(r'^rem cmd\s', user_data, re.I):
        target_path += '.cmd'
        args = [target_path]
        shell = True
    elif re.search(r'^#!/usr/bin/env\spython\s', user_data, re.I):
        target_path += '.py'
        args = ['python.exe', target_path]
        shell = False
    elif re.search(r'^#!', user_data, re.I):
        target_path += '.sh'
        args = ['bash.exe', target_path]
        shell = False
    elif re.search(r'^#ps1\s', user_data, re.I):
        target_path += '.ps1'
        args = ['powershell.exe', '-ExecutionPolicy', 'RemoteSigned',
                '-NonInteractive', target_path]
        shell = False
    elif re.search(r'^#ps1_sysnative\s', user_data, re.I):
        if os.path.isdir(os.path.expandvars('%windir%\\sysnative')):
            target_path += '.ps1'
            args = [os.path.expandvars('%windir%\\sysnative\\'
                                       'WindowsPowerShell\\v1.0\\'
                                       'powershell.exe'),
                    '-ExecutionPolicy',
                    'RemoteSigned', '-NonInteractive', target_path]
            shell = False
        else:
            # Unable to validate sysnative presence
            LOG.warning('Unable to validate sysnative folder presence. '
                        'If Target OS is Server 2003, please ensure you '
                        'have KB942589 installed')
            return 0
    else:
        # Unsupported
        LOG.warning('Unsupported user_data format')
        return 0

    try:
        with open(target_path, 'wb') as f:
            f.write(user_data)
        (out, err, ret_val) = osutils.execute_process(args, shell)

        LOG.info('User_data script ended with return code: %d' % ret_val)
        LOG.debug('User_data stdout:\n%s' % out)
        LOG.debug('User_data stderr:\n%s' % err)

        return ret_val
    except Exception, ex:
        LOG.warning('An error occurred during user_data execution: \'%s\''
                    % ex)
    finally:
        if os.path.exists(target_path):
            os.remove(target_path)
