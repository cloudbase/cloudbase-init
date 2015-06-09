# Copyright 2013 Cloudbase Solutions Srl
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

from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import sethostname
from cloudbaseinit.tests import testutils


class SetHostNamePluginPluginTests(unittest.TestCase):

    def setUp(self):
        self._sethostname_plugin = sethostname.SetHostNamePlugin()

    @testutils.ConfPatcher('netbios_host_name_compatibility', True)
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.utils.hostname.set_hostname')
    def _test_execute(self, mock_set_hostname, mock_get_os_utils,
                      hostname_exists=False):
        new_hostname = 'hostname'
        shared_data = 'fake_shared_data'
        mock_get_os_utils.return_value = None
        mock_service = mock.MagicMock()
        if hostname_exists:
            mock_service.get_host_name.return_value = new_hostname
        else:
            mock_service.get_host_name.return_value = None
        mock_set_hostname.return_value = (new_hostname, True)

        response = self._sethostname_plugin.execute(mock_service, shared_data)

        mock_service.get_host_name.assert_called_once_with()

        if hostname_exists:
            mock_set_hostname.assert_called_once_with(
                None, new_hostname)
        else:
            self.assertFalse(mock_set_hostname.called)

        self.assertEqual((base.PLUGIN_EXECUTION_DONE, hostname_exists),
                         response)

    def test_execute_new_hostname(self):
        self._test_execute(hostname_exists=True)

    def test_execute_no_hostname(self):
        self._test_execute(hostname_exists=False)
