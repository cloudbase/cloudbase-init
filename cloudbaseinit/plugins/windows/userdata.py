# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import os
import re
import tempfile
import uuid

from cloudbaseinit.metadata.services import base as metadata_services_base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base

LOG = logging.getLogger(__name__)


class UserDataPlugin(base.BasePlugin):
    def execute(self, service):
        try:
            user_data = service.get_user_data('openstack')
        except metadata_services_base.NotExistingMetadataException:
            return (base.PLUGIN_EXECUTION_DONE, False)

        if not user_data:
            return (base.PLUGIN_EXECUTION_DONE, False)

        LOG.debug('User data content:\n%s' % user_data)

        osutils = osutils_factory.OSUtilsFactory().get_os_utils()

        target_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
        if re.search(r'^rem cmd\s', user_data, re.I):
            target_path += '.cmd'
            args = [target_path]
            shell = True
        elif re.search(r'^#!', user_data, re.I):
            target_path += '.sh'
            args = ['bash.exe', target_path]
            shell = False
        elif re.search(r'^#ps1\s', user_data, re.I):
            target_path += '.ps1'
            args = ['powershell.exe', '-ExecutionPolicy', 'RemoteSigned',
                    '-NonInteractive', target_path]
            shell = False
        else:
            # Unsupported
            LOG.warning('Unsupported user_data format')
            return (base.PLUGIN_EXECUTION_DONE, False)

        try:
            with open(target_path, 'wb') as f:
                f.write(user_data)
            (out, err, ret_val) = osutils.execute_process(args, shell)

            LOG.info('User_data script ended with return code: %d' % ret_val)
            LOG.debug('User_data stdout:\n%s' % out)
            LOG.debug('User_data stderr:\n%s' % err)
        except Exception, ex:
            LOG.warning('An error occurred during user_data execution: \'%s\''
                        % ex)
        finally:
            if os.path.exists(target_path):
                os.remove(target_path)

        return (base.PLUGIN_EXECUTION_DONE, False)
