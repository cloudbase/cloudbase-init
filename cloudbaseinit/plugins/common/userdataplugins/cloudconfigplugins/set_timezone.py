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


LOG = oslo_logging.getLogger(__name__)


class SetTimezonePlugin(base.BaseCloudConfigPlugin):
    """Change the timezone for the underlying platform.

    This uses IANA timezone names (which are mapped to the Windows
    time zone names, as seen in the following link:
    https://technet.microsoft.com/en-us/library/cc749073%28v=ws.10%29.aspx).

    For instance, to change the timezone to 'America/Montevideo', use
    this syntax::

        set_timezone: America/Montevideo

    """

    def process(self, data):
        LOG.info("Changing timezone to %r", data)
        osutils = factory.get_os_utils()
        osutils.set_timezone(data)
