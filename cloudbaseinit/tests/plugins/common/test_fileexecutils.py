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

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.plugins.common import execcmd
from cloudbaseinit.plugins.common import fileexecutils
from cloudbaseinit.tests import testutils


@mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
class TestFileExecutilsPlugin(unittest.TestCase):

    def test_exec_file_no_executor(self, _):
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'fileexecutils') as snatcher:
            retval = fileexecutils.exec_file("fake.fake")

        expected_logging = ['Unsupported script file type: fake']
        self.assertEqual(0, retval)
        self.assertEqual(expected_logging, snatcher.output)

    def test_executors_mapping(self, _):
        self.assertEqual(fileexecutils.FORMATS["cmd"],
                         execcmd.Shell)
        self.assertEqual(fileexecutils.FORMATS["exe"],
                         execcmd.Shell)
        self.assertEqual(fileexecutils.FORMATS["sh"],
                         execcmd.Bash)
        self.assertEqual(fileexecutils.FORMATS["py"],
                         execcmd.Python)
        self.assertEqual(fileexecutils.FORMATS["ps1"],
                         execcmd.PowershellSysnative)

    @mock.patch('cloudbaseinit.plugins.common.execcmd.'
                'BaseCommand.execute')
    def test_exec_file_fails(self, mock_execute, _):
        mock_execute.side_effect = ValueError
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'fileexecutils') as snatcher:
            retval = fileexecutils.exec_file("fake.py")

        expected_logging = [
            "An error occurred during file execution: ''",
            'Script "fake.py" ended with exit code: 0'
        ]
        mock_execute.assert_called_once_with()
        self.assertEqual(0, retval)
        self.assertEqual(expected_logging, snatcher.output)

    @mock.patch('cloudbaseinit.plugins.common.execcmd.'
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
