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

import time

from cloudbaseinit import exception
from cloudbaseinit.plugins.common import ntpclient


_W32TIME_SERVICE = "w32time"


class NTPClientPlugin(ntpclient.NTPClientPlugin):

    @staticmethod
    def _set_ntp_trigger_mode(osutils):
        """Set the trigger mode for w32time service to network availability.

        This function changes the triggers for the w32time service, so that
        the service will always work when there's networking, but will
        stop itself whenever this condition stops being true.
        It also changes the current triggers of the service (domain joined
        for instance).
        """
        args = ["sc.exe", "triggerinfo", _W32TIME_SERVICE,
                "start/networkon", "stop/networkoff"]
        return osutils.execute_system32_process(args)

    def verify_time_service(self, osutils):
        """Verify that the time service is up and try to start it."""

        svc_start_mode = osutils.get_service_start_mode(
            _W32TIME_SERVICE)

        if svc_start_mode != osutils.SERVICE_START_MODE_AUTOMATIC:
            osutils.set_service_start_mode(
                _W32TIME_SERVICE,
                osutils.SERVICE_START_MODE_AUTOMATIC)

        if osutils.check_os_version(6, 1):
            self._set_ntp_trigger_mode(osutils)

        svc_status = osutils.get_service_status(_W32TIME_SERVICE)
        if svc_status == osutils.SERVICE_STATUS_STOPPED:
            osutils.start_service(_W32TIME_SERVICE)

            i = 0
            max_retries = 30
            while svc_status != osutils.SERVICE_STATUS_RUNNING:
                if i >= max_retries:
                    raise exception.CloudbaseInitException(
                        'Service %s did not start' % _W32TIME_SERVICE)
                time.sleep(1)
                svc_status = osutils.get_service_status(_W32TIME_SERVICE)
                i += 1
        super(NTPClientPlugin, self).verify_time_service(osutils)
