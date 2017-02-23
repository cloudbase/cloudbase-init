# Copyright 2016 Cloudbase Solutions Srl
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
    set_hostname
)


CONF = cfg.CONF


class Set_HostNamePluginPluginTest(unittest.TestCase):

    def setUp(self):
        self._sethost_name_plugin = set_hostname.SetHostnamePlugin()

    @mock.patch('cloudbaseinit.utils.hostname')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process(self, mock_get_os_utils, mock_hostname):
        mock_data = "fake_data"
        mock_os_util = mock.MagicMock()
        mock_os_util.set_hostname.return_value = (mock_data, True)
        mock_get_os_utils.return_value = mock_os_util
        result_process = self._sethost_name_plugin.process(mock_data)
        self.assertTrue(result_process)
