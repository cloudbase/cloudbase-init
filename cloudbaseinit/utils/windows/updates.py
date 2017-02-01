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

import random

from win32com import client

from cloudbaseinit.osutils import factory as osutils_factory

AU_DISABLED = 1
AU_SCHEDULED_INSTALLATION = 4

MIN_INSTALL_HOUR = 1
MAX_INSTALL_HOUR = 5


def set_automatic_updates(enabled):
    # TODO(alexpilotti): the following settings are ignored on
    # Windows 10 / Windows Server 2016 build 14393
    auto_update = client.Dispatch("Microsoft.Update.AutoUpdate")
    if enabled:
        auto_update.Settings.NotificationLevel = AU_SCHEDULED_INSTALLATION
        osutils = osutils_factory.get_os_utils()
        if not osutils.check_os_version(6, 2):
            # NOTE(alexpilotti): this setting is not supported starting
            # with Windows 8 / Windows Server 2012
            hour = random.randint(MIN_INSTALL_HOUR, MAX_INSTALL_HOUR)
            auto_update.SettingsScheduledInstallationTime = hour
    else:
        auto_update.Settings.NotificationLevel = AU_DISABLED

    auto_update.Settings.Save()
