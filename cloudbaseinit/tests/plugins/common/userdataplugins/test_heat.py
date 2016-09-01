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

import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common.userdataplugins import heat

CONF = cloudbaseinit_conf.CONF


class HeatUserDataHandlerTests(unittest.TestCase):

    def setUp(self):
        self._heat = heat.HeatPlugin()

    @mock.patch('os.path.exists')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.dirname')
    def test_check_heat_config_dir(self, mock_dirname, mock_makedirs,
                                   mock_exists):
        mock_exists.return_value = False
        fake_path = mock.sentinel.fake_path
        fake_dir = mock.sentinel.fake_dir
        mock_dirname.return_value = fake_dir

        self._heat._check_dir(file_name=fake_path)

        mock_dirname.assert_called_once_with(fake_path)
        mock_exists.assert_called_once_with(fake_dir)
        mock_makedirs.assert_called_once_with(fake_dir)

    @mock.patch('cloudbaseinit.plugins.common.userdatautils'
                '.execute_user_data_script')
    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.heat'
                '.HeatPlugin._check_dir')
    @mock.patch('cloudbaseinit.utils.encoding.write_file')
    def _test_process(self, mock_write_file, mock_check_dir,
                      mock_execute_user_data_script, filename):
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = filename
        response = self._heat.process(mock_part)

        path = os.path.join(CONF.heat_config_dir, filename)
        mock_check_dir.assert_called_once_with(path)
        mock_part.get_filename.assert_called_with()
        mock_write_file.assert_called_once_with(
            path, mock_part.get_payload.return_value)

        if filename == self._heat._heat_user_data_filename:
            mock_execute_user_data_script.assert_called_with(
                mock_part.get_payload())
            self.assertEqual(mock_execute_user_data_script.return_value,
                             response)
        else:
            self.assertTrue(response is None)

    def test_process(self):
        self._test_process(filename=self._heat._heat_user_data_filename)

    def test_process_content_other_data(self):
        self._test_process(filename='other data')
