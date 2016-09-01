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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class WindowsLicensingPlugin(base.BasePlugin):

    def _run_slmgr(self, osutils, args):
        if osutils.check_sysnative_dir_exists():
            cscript_dir = osutils.get_sysnative_dir()
        else:
            cscript_dir = osutils.get_system32_dir()

        # Not SYSNATIVE, as it is already executed by a x64 process
        slmgr_dir = osutils.get_system32_dir()

        cscript_path = os.path.join(cscript_dir, "cscript.exe")
        slmgr_path = os.path.join(slmgr_dir, "slmgr.vbs")

        (out, err, exit_code) = osutils.execute_process(
            [cscript_path, slmgr_path] + args, shell=False, decode_output=True)

        if exit_code:
            raise exception.CloudbaseInitException(
                'slmgr.vbs failed with error code %(exit_code)s.\n'
                'Output: %(out)s\nError: %(err)s' % {'exit_code': exit_code,
                                                     'out': out, 'err': err})
        return out

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()

        if osutils.is_nano_server():
            LOG.info("Licensing info and activation are not available on "
                     "Nano Server")
        else:
            license_info = self._run_slmgr(osutils, ['/dlv'])
            LOG.info('Microsoft Windows license info:\n%s' % license_info)

            if CONF.activate_windows:
                LOG.info("Activating Windows")
                activation_result = self._run_slmgr(osutils, ['/ato'])
                LOG.debug("Activation result:\n%s" % activation_result)

        return base.PLUGIN_EXECUTION_DONE, False
