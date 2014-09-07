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
    osutils = osutils_factory.get_os_utils()

    shell = False
    powershell = False
    sysnative = True

    target_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
    if re.search(r'^rem cmd\s', user_data, re.I):
        target_path += '.cmd'
        args = [target_path]
        shell = True
    elif re.search(r'^#!/usr/bin/env\spython\s', user_data, re.I):
        target_path += '.py'
        args = ['python.exe', target_path]
    elif re.search(r'^#!', user_data, re.I):
        target_path += '.sh'
        args = ['bash.exe', target_path]
    elif re.search(r'^#(ps1|ps1_sysnative)\s', user_data, re.I):
        target_path += '.ps1'
        powershell = True
    elif re.search(r'^#ps1_x86\s', user_data, re.I):
        target_path += '.ps1'
        powershell = True
        sysnative = False
    else:
        # Unsupported
        LOG.warning('Unsupported user_data format')
        return 0

    try:
        with open(target_path, 'wb') as f:
            f.write(user_data)

        if powershell:
            (out, err,
             ret_val) = osutils.execute_powershell_script(target_path,
                                                          sysnative)
        else:
            (out, err, ret_val) = osutils.execute_process(args, shell)

        LOG.info('User_data script ended with return code: %d' % ret_val)
        LOG.debug('User_data stdout:\n%s' % out)
        LOG.debug('User_data stderr:\n%s' % err)

        return ret_val
    except Exception as ex:
        LOG.warning('An error occurred during user_data execution: \'%s\''
                    % ex)
    finally:
        if os.path.exists(target_path):
            os.remove(target_path)
