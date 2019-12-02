# Copyright 2019 Cloudbase Solutions Srl
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
import six

from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.osutils import factory
from cloudbaseinit.plugins.common import execcmd
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    base
)
from cloudbaseinit.plugins.common import userdatautils

LOG = oslo_logging.getLogger(__name__)


class RunCmdPlugin(base.BaseCloudConfigPlugin):
    """Aggregate and execute cloud-config runcmd entries in a shell.

       The runcmd entries can be a string or an array of strings.
       The prefered shell is given by the OS platform.

       Example for Windows, where cmd.exe is the prefered shell:

         #cloud-config

         runcmd:
           - ['dir', 'C:\']
           - 'dir C:\'
    """

    @staticmethod
    def _unify_scripts(commands, env_header):
        script_content = env_header + os.linesep

        entries = 0
        for command in commands:
            if isinstance(command, six.string_types):
                script_content += command
            elif isinstance(command, (list, tuple)):
                subcommand_content = []
                for subcommand in command:
                    subcommand_content.append("%s" % subcommand)
                script_content += ' '.join(subcommand_content)
            else:
                raise exception.CloudbaseInitException(
                    "Unrecognized type '%r' in cmd content" % type(command))

            script_content += os.linesep
            entries += 1

        LOG.info("Found %d cloud-config runcmd entries." % entries)
        return script_content

    def process(self, data):
        if not data:
            LOG.info('No cloud-config runcmd entries found.')
            return

        LOG.info("Running cloud-config runcmd entries.")
        osutils = factory.get_os_utils()
        env_header = osutils.get_default_script_exec_header()

        try:
            ret_val = userdatautils.execute_user_data_script(
                self._unify_scripts(data, env_header).encode())
            _, reboot = execcmd.get_plugin_return_value(ret_val)
            return reboot
        except Exception as ex:
            LOG.warning("An error occurred during runcmd execution: '%s'"
                        % ex)
        return False
