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

from oslo.config import cfg

from cloudbaseinit.plugins.windows.userdataplugins import heat

CONF = cfg.CONF


class HeatUserDataHandlerTests(unittest.TestCase):

    def setUp(self):
        self._heat = heat.HeatPlugin()

    @mock.patch('os.path.exists')
    @mock.patch('os.makedirs')
    def test_check_heat_config_dir(self, mock_makedirs, mock_exists):
        mock_exists.return_value = False
        self._heat._check_heat_config_dir()
        mock_exists.assert_called_once_with(CONF.heat_config_dir)
        mock_makedirs.assert_called_once_with(CONF.heat_config_dir)

    @mock.patch('cloudbaseinit.plugins.windows.userdatautils'
                '.execute_user_data_script')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.heat'
                '.HeatPlugin._check_heat_config_dir')
    def _test_process(self, mock_check_heat_config_dir,
                      mock_execute_user_data_script, filename):
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = filename
        with mock.patch('six.moves.builtins.open', mock.mock_open(),
                        create=True) as handle:
            response = self._heat.process(mock_part)
            handle().write.assert_called_once_with(mock_part.get_payload())
        mock_check_heat_config_dir.assert_called_once_with()
        mock_part.get_filename.assert_called_with()
        if filename == self._heat._heat_user_data_filename:
            mock_execute_user_data_script.assert_called_with(
                mock_part.get_payload())
            self.assertEqual(response, mock_execute_user_data_script())
        else:
            self.assertTrue(response is None)

    def test_process(self):
        self._test_process(filename=self._heat._heat_user_data_filename)

    def test_process_content_other_data(self):
        self._test_process(filename='other data')
