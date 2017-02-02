# Copyright (c) 2017 Cloudbase Solutions Srl
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

from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory


def set_display_idle_timeout(seconds=0):
    osutils = osutils_factory.get_os_utils()
    args = ["powercfg.exe", "/setacvalueindex", "SCHEME_CURRENT",
            "SUB_VIDEO", "VIDEOIDLE", str(int(seconds))]
    (out, err, ret_val) = osutils.execute_system32_process(args)
    if ret_val:
        raise exception.CloudbaseInitException(
            'PowerCfg failed.\nOutput: %(out)s\nError:'
            ' %(err)s' % {'out': out, 'err': err})
