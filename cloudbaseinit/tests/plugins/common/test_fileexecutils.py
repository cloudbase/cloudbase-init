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

from cloudbaseinit.plugins.common import fileexecutils
from cloudbaseinit.tests import testutils


@mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
class TestFileExecutilsPlugin(unittest.TestCase):

    @mock.patch('cloudbaseinit.plugins.common.userdatautils.'
                'get_command_from_path')
    @mock.patch('cloudbaseinit.plugins.common.userdatautils.'
                'execute_user_data_script')
    def test_exec_file_no_executor(self, mock_execute_user_data_script,
                                   mock_get_command, _):
        mock_get_command.return_value = None
        with testutils.create_tempfile() as temp:
            with mock.patch('cloudbaseinit.plugins.common.userdatautils'
                            '.open', create=True):
                with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                           'fileexecutils') as snatcher:
                    retval = fileexecutils.exec_file(temp)

        expected_logging = ['No valid extension or header found'
                            ' in the userdata: %s' % temp]
        self.assertEqual(0, retval)
        self.assertEqual(expected_logging, snatcher.output)

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
        mock_execute.return_value = (mock.sentinel.out, mock.sentinel.error, 0)
        retval = fileexecutils.exec_file("fake.py")
        mock_execute.assert_called_once_with()
        self.assertEqual(0, retval)
