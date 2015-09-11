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


from cloudbaseinit.plugins.common.userdataplugins import shellscript
from cloudbaseinit.tests import testutils


class ShellScriptPluginTests(unittest.TestCase):

    def setUp(self):
        self._shellscript = shellscript.ShellScriptPlugin()

    @mock.patch('os.path.exists')
    @mock.patch('os.remove')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('tempfile.gettempdir')
    @mock.patch('cloudbaseinit.plugins.common.fileexecutils.exec_file')
    @mock.patch('cloudbaseinit.utils.encoding.write_file')
    def _test_process(self, mock_write_file, mock_exec_file, mock_gettempdir,
                      mock_get_os_utils, mock_os_remove,
                      mock_path_exists, exception=False):

        mock_path_exists.return_value = True
        fake_dir_path = os.path.join("fake", "dir")
        mock_osutils = mock.MagicMock()
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = "fake_filename"
        mock_gettempdir.return_value = fake_dir_path
        mock_get_os_utils.return_value = mock_osutils
        fake_target = os.path.join(fake_dir_path, "fake_filename")
        mock_exec_file.return_value = 'fake response'

        if exception:
            mock_exec_file.side_effect = [Exception]
        with mock.patch("cloudbaseinit.plugins.common.userdataplugins."
                        "shellscript.open", mock.mock_open(), create=True):
            with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                       'userdataplugins.'
                                       'shellscript') as snatcher:
                response = self._shellscript.process(mock_part)

        mock_part.get_filename.assert_called_once_with()
        mock_write_file.assert_called_once_with(
            fake_target, mock_part.get_payload.return_value)
        mock_exec_file.assert_called_once_with(fake_target)
        mock_part.get_payload.assert_called_once_with()
        mock_gettempdir.assert_called_once_with()
        if not exception:
            self.assertEqual('fake response', response)
        else:
            expected_logging = 'An error occurred during user_data execution'
            self.assertTrue(snatcher.output[0].startswith(expected_logging))

        mock_os_remove.assert_called_once_with(fake_target)
        mock_path_exists.assert_called_once_with(fake_target)

    def test_process(self):
        self._test_process(exception=False)

    def test_process_exception(self):
        self._test_process(exception=True)
