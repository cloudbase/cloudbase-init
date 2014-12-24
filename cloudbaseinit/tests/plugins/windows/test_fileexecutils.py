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

import unittest

import mock

from cloudbaseinit.plugins.common import executil
from cloudbaseinit.plugins.windows import fileexecutils


@mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
class TestFileExecutilsPlugin(unittest.TestCase):

    def test_exec_file_no_executor(self, _):
        retval = fileexecutils.exec_file("fake.fake")
        self.assertEqual(0, retval)

    def test_executors_mapping(self, _):
        self.assertEqual(fileexecutils.FORMATS["cmd"],
                         executil.Shell)
        self.assertEqual(fileexecutils.FORMATS["exe"],
                         executil.Shell)
        self.assertEqual(fileexecutils.FORMATS["sh"],
                         executil.Bash)
        self.assertEqual(fileexecutils.FORMATS["py"],
                         executil.Python)
        self.assertEqual(fileexecutils.FORMATS["ps1"],
                         executil.PowershellSysnative)

    @mock.patch('cloudbaseinit.plugins.common.executil.'
                'BaseCommand.execute')
    def test_exec_file_fails(self, mock_execute, _):
        mock_execute.side_effect = ValueError
        retval = fileexecutils.exec_file("fake.py")
        mock_execute.assert_called_once_with()
        self.assertEqual(0, retval)

    @mock.patch('cloudbaseinit.plugins.common.executil.'
                'BaseCommand.execute')
    def test_exec_file_(self, mock_execute, _):
        mock_execute.return_value = (
            mock.sentinel.out,
            mock.sentinel.error,
            0,
        )
        retval = fileexecutils.exec_file("fake.py")
        mock_execute.assert_called_once_with()
        self.assertEqual(0, retval)
