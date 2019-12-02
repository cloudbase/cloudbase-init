# Copyright 2019 Cloudbase Solutions Srl
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

from oslo_config import cfg

from cloudbaseinit import exception
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    runcmd
)

from cloudbaseinit.tests import testutils

CONF = cfg.CONF


class RunCmdPluginTest(unittest.TestCase):

    def setUp(self):
        self._runcmd_plugin = runcmd.RunCmdPlugin()

    def test_unify_scripts(self):
        run_commands = ['echo 1', 'echo 2']
        fake_hader = 'fake_header'

        result = self._runcmd_plugin._unify_scripts(run_commands, fake_hader)

        ln_sep = os.linesep
        expected_result = 'fake_header%secho 1%secho 2%s' % (ln_sep, ln_sep,
                                                             ln_sep,)
        self.assertEqual(result, expected_result)

    def test_unify_scripts_fail(self):
        run_commands = [{'cmd': 'fake_cmd'}]
        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self._runcmd_plugin._unify_scripts(run_commands, 'fake_header')

        expected = ("Unrecognized type '%s' in cmd content"
                    % type(run_commands[0]))
        self.assertEqual(expected, str(cm.exception))

    @mock.patch('cloudbaseinit.plugins.common.'
                'userdatautils.execute_user_data_script')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_basic_data(self, mock_os_utils, mock_userdata):
        run_commands = ['echo 1', 'echo 2', ['echo', '1'], 'exit 1003']
        mock_userdata.return_value = 1003
        mock_utils = mock.MagicMock()
        mock_utils.get_default_script_exec_header.return_value = 'fake_header'
        mock_os_utils.return_value = mock_utils
        expected_logging = [
            "Running cloud-config runcmd entries.",
            "Found 4 cloud-config runcmd entries.",
        ]
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'runcmd') as snatcher:
            result_process = self._runcmd_plugin.process(run_commands)

        mock_utils.get_default_script_exec_header.assert_called_with()
        self.assertEqual(expected_logging, snatcher.output)
        self.assertEqual(result_process, True)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_wrong_cmd_type(self, mock_os_utils):
        run_commands = [{'cmd': 'fake_cmd'}]
        expected_logging = [
            "Running cloud-config runcmd entries.",
            "An error occurred during runcmd execution: 'Unrecognized type "
            "'%s' in cmd content'" % type(run_commands[0])
        ]
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'runcmd') as snatcher:
            result_process = self._runcmd_plugin.process(run_commands)

        self.assertEqual(expected_logging, snatcher.output)
        self.assertEqual(result_process, False)
