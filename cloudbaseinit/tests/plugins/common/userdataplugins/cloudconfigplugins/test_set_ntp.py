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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from oslo_config import cfg

from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    set_ntp
)


CONF = cfg.CONF


class SetNtpPluginTest(unittest.TestCase):

    def setUp(self):
        self._set_ntp = set_ntp.SetNtpPlugin()

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_process(self, mock_data, mock_get_os_utils):
        mock_os_util = mock.MagicMock()
        mock_os_util.set_ntp_client_config.return_value = True
        mock_get_os_utils.return_value = mock_os_util
        result_process = self._set_ntp.process(mock_data)
        self.assertFalse(result_process)

    def test_process_no_servers(self):
        self._test_process({})

    def test_process_servers_pools(self):
        self._test_process({'servers': ['one', 'two'], 'pools': 'one'})
