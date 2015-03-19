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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.plugins.common.userdataplugins import cloudconfig
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    set_timezone
)
from cloudbaseinit.tests import testutils


class TestSetTimezone(unittest.TestCase):

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.'
                'cloudconfigplugins.set_timezone.factory')
    def test_process(self, mock_osutils_factory):
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'set_timezone') as snatcher:
            set_timezone.SetTimezonePlugin().process(mock.sentinel.timezone)

        expected_logging = [
            'Changing timezone to %r' % mock.sentinel.timezone
        ]
        mock_osutils_factory.get_os_utils.assert_called_once_with()
        mock_osutils = mock_osutils_factory.get_os_utils.return_value
        mock_osutils.set_timezone.assert_called_once_with(
            mock.sentinel.timezone)
        self.assertEqual(expected_logging, snatcher.output)

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.'
                'cloudconfigplugins.set_timezone.SetTimezonePlugin.process')
    def test_timezone_dispatch(self, mock_process_plugin):
        plugin = cloudconfig.CloudConfigPlugin()
        plugin.process_non_multipart("set_timezone: America Standard Time")

        mock_process_plugin.assert_called_once_with("America Standard Time")
