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

import mock
import unittest

from cloudbaseinit.plugins.windows import fileexecutils


class TestFileExecutilsPlugin(unittest.TestCase):

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_exec_file(self, mock_get_os_utils, filename, exception=False):
        mock_osutils = mock.MagicMock()
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = filename
        mock_get_os_utils.return_value = mock_osutils
        if exception:
            mock_osutils.execute_process.side_effect = [Exception]
        with mock.patch("cloudbaseinit.plugins.windows.userdataplugins."
                        "shellscript.open", mock.mock_open(), create=True):
            response = fileexecutils.exec_file(filename)
        if filename.endswith(".cmd"):
            mock_osutils.execute_process.assert_called_once_with(
                [filename], True)
        elif filename.endswith(".sh"):
            mock_osutils.execute_process.assert_called_once_with(
                ['bash.exe', filename], False)
        elif filename.endswith(".py"):
            mock_osutils.execute_process.assert_called_once_with(
                ['python.exe', filename], False)
        elif filename.endswith(".exe"):
            mock_osutils.execute_process.assert_called_once_with(
                [filename], False)
        elif filename.endswith(".ps1"):
            mock_osutils.execute_powershell_script.assert_called_once_with(
                filename)
        else:
            self.assertEqual(0, response)

    def test_process_cmd(self):
        self._test_exec_file(filename='fake.cmd')

    def test_process_sh(self):
        self._test_exec_file(filename='fake.sh')

    def test_process_py(self):
        self._test_exec_file(filename='fake.py')

    def test_process_ps1(self):
        self._test_exec_file(filename='fake.ps1')

    def test_process_other(self):
        self._test_exec_file(filename='fake.other')

    def test_process_exe(self):
        self._test_exec_file(filename='fake.exe')

    def test_process_exception(self):
        self._test_exec_file(filename='fake.exe', exception=True)
