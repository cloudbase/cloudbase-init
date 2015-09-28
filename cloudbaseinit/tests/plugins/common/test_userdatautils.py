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


import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.plugins.common import execcmd
from cloudbaseinit.plugins.common import userdatautils
from cloudbaseinit.tests import testutils


def _safe_remove(filepath):
    if not filepath:
        return
    try:
        os.remove(filepath)
    except OSError:
        pass


@mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
class UserDataUtilsTest(unittest.TestCase):

    def _get_command(self, data):
        """Get a command from the given data.

        If a command was obtained, then a cleanup will be added in order
        to remove the underlying target path of the command.
        """
        command = userdatautils._get_command(data)
        if command and not isinstance(command, execcmd.CommandExecutor):
            self.addCleanup(_safe_remove, command._target_path)
        return command

    def test__get_command(self, _):
        command = self._get_command(b'rem cmd test')
        self.assertIsInstance(command, execcmd.Shell)

        command = self._get_command(b'#!/usr/bin/env python\ntest')
        self.assertIsInstance(command, execcmd.Python)

        command = self._get_command(b'#!/bin/bash')
        self.assertIsInstance(command, execcmd.Bash)

        command = self._get_command(b'#ps1_sysnative\n')
        self.assertIsInstance(command, execcmd.PowershellSysnative)

        command = self._get_command(b'#ps1_x86\n')
        self.assertIsInstance(command, execcmd.Powershell)

        command = self._get_command(b'<script>echo test</script>')
        self.assertIsInstance(command, execcmd.CommandExecutor)

        command = self._get_command(b'unknown')
        self.assertIsNone(command)

    def test_execute_user_data_script_no_commands(self, _):
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdatautils') as snatcher:
            retval = userdatautils.execute_user_data_script(b"unknown")

        expected_logging = [
            'Unsupported user_data format'
        ]
        self.assertEqual(0, retval)
        self.assertEqual(expected_logging, snatcher.output)

    @mock.patch('cloudbaseinit.plugins.common.userdatautils.'
                '_get_command')
    def test_execute_user_data_script_fails(self, mock_get_command, _):
        mock_get_command.return_value.side_effect = ValueError

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdatautils') as snatcher:
            retval = userdatautils.execute_user_data_script(
                mock.sentinel.user_data)

        expected_logging = [
            "An error occurred during user_data execution: ''",
            'User_data script ended with return code: 0'
        ]
        self.assertEqual(0, retval)
        self.assertEqual(expected_logging, snatcher.output)

    @mock.patch('cloudbaseinit.plugins.common.userdatautils.'
                '_get_command')
    def test_execute_user_data_script(self, mock_get_command, _):
        mock_get_command.return_value.return_value = (
            mock.sentinel.output, mock.sentinel.error, -1
        )
        retval = userdatautils.execute_user_data_script(
            mock.sentinel.user_data)
        self.assertEqual(-1, retval)
