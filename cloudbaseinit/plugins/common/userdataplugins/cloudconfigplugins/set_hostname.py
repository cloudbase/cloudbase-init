# Copyright 2015 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging

from cloudbaseinit.osutils import factory
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    base
)
from cloudbaseinit.utils import hostname


LOG = oslo_logging.getLogger(__name__)


class SetHostnamePlugin(base.BaseCloudConfigPlugin):
    """Change the hostname for the underlying platform.

    If the timezone is changed a restart will be required.

    """

    def process(self, data):
        LOG.info("Changing hostname to %r", data)
        osutils = factory.get_os_utils()
        _, reboot_required = hostname.set_hostname(osutils, data)
        return reboot_required
