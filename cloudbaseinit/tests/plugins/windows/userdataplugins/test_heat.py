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
from cloudbaseinit.plugins.windows.userdataplugins import heat

CONF = cfg.CONF


class HeatUserDataHandlerTests(unittest.TestCase):

    def setUp(self):
        self._heat = heat.HeatPlugin()

    @mock.patch('cloudbaseinit.plugins.windows.userdatautils'
                '.execute_user_data_script')
    def _test_process(self, mock_execute_user_data_script, filename):
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = filename
        response = self._heat.process(mock_part)
        mock_part.get_filename.assert_called_with()
        if filename:
            mock_execute_user_data_script.assert_called_with(
                mock_part.get_payload())
            self.assertEqual(response, mock_execute_user_data_script())
        else:
            self.assertTrue(response is None)

    def test_process(self):
        self._test_process(filename='cfn-userdata')

    def test_process_content_not_supported(self):
        self._test_process(filename=None)
