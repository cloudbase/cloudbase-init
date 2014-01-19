# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import mock
import unittest

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.plugins.windows import sethostname
from cloudbaseinit.tests.metadata import fake_json_response

CONF = cfg.CONF


class SetHostNamePluginPluginTests(unittest.TestCase):

    def setUp(self):
        self._sethostname_plugin = sethostname.SetHostNamePlugin()
        self.fake_data = fake_json_response.get_fake_metadata_json(
            '2013-04-04')

    @mock.patch('cloudbaseinit.osutils.factory.OSUtilsFactory.get_os_utils')
    def _test_execute(self, mock_get_os_utils, hostname_exists):
        mock_service = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        fake_shared_data = 'fake data'
        mock_service.get_meta_data.return_value = self.fake_data
        if hostname_exists is False:
            del self.fake_data['hostname']
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.set_host_name.return_value = False
        response = self._sethostname_plugin.execute(mock_service,
                                                    fake_shared_data)
        mock_service.get_meta_data.assert_called_once_with('openstack')
        if hostname_exists is True:
            mock_get_os_utils.assert_called_once_with()
            mock_osutils.set_host_name.assert_called_once_with(
                self.fake_data['hostname'].split('.', 1)[0])
        self.assertEqual(response, (1, False))

    def test_execute(self):
        self._test_execute(hostname_exists=True)

    def test_execute_no_hostname(self):
        self._test_execute(hostname_exists=False)
