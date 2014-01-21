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
import os
import uuid
import unittest

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.plugins.windows import userdatautils
from cloudbaseinit.tests.metadata import fake_json_response

CONF = cfg.CONF


class UserDataUtilsTest(unittest.TestCase):

    def setUp(self):
        self.fake_data = fake_json_response.get_fake_metadata_json(
            '2013-04-04')

    @mock.patch('re.search')
    @mock.patch('tempfile.gettempdir')
    @mock.patch('os.remove')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.expandvars')
    @mock.patch('cloudbaseinit.osutils.factory.OSUtilsFactory.get_os_utils')
    def _test_execute_user_data_script(self, mock_get_os_utils,
                                       mock_path_expandvars,
                                       mock_path_exists, mock_path_isdir,
                                       mock_os_remove, mock_gettempdir,
                                       mock_re_search, fake_user_data,
                                       directory_exists):
        mock_osutils = mock.MagicMock()
        mock_gettempdir.return_value = 'fake_temp'
        uuid.uuid4 = mock.MagicMock(return_value='randomID')
        match_instance = mock.MagicMock()
        path = os.path.join('fake_temp', 'randomID')
        args = None
        mock_get_os_utils.return_value = mock_osutils
        if fake_user_data == '^rem cmd\s':
            side_effect = [match_instance]
            number_of_calls = 1
            extension = '.cmd'
            args = [path+extension]
            shell = True
        elif fake_user_data == '^#!/usr/bin/env\spython\s':
            side_effect = [None, match_instance]
            number_of_calls = 2
            extension = '.py'
            args = ['python.exe', path+extension]
            shell = False
        elif fake_user_data == '#!':
            side_effect = [None, None, match_instance]
            number_of_calls = 3
            extension = '.sh'
            args = ['bash.exe', path+extension]
            shell = False
        elif fake_user_data == '#ps1\s':
            side_effect = [None, None, None, match_instance]
            number_of_calls = 4
            extension = '.ps1'
            args = ['powershell.exe', '-ExecutionPolicy', 'RemoteSigned',
                    '-NonInteractive', path+extension]
            shell = False
        else:
            side_effect = [None, None, None, None, match_instance]
            number_of_calls = 5
            extension = '.ps1'
            shell = False
            if directory_exists:
                args = [mock_path_expandvars('%windir%\\sysnative\\'
                                             'WindowsPowerShell\\v1.0\\'
                                             'powershell.exe'),
                        '-ExecutionPolicy',
                        'RemoteSigned', '-NonInteractive', path+extension]
                mock_path_isdir.return_value = True
            else:
                mock_path_isdir.return_value = False

        mock_re_search.side_effect = side_effect

        with mock.patch('cloudbaseinit.plugins.windows.userdatautils.open',
                        mock.mock_open(), create=True):
            response = userdatautils.execute_user_data_script(fake_user_data)
        mock_gettempdir.assert_called_once_with()
        self.assertEqual(mock_re_search.call_count, number_of_calls)
        if args:
            mock_osutils.execute_process.assert_called_with(args, shell)
        if not directory_exists:
            self.assertEqual(response, 0)
        else:
            self.assertEqual(response, None)

    def test_handle_batch(self):
        fake_user_data = '^rem cmd\s'
        self._test_execute_user_data_script(fake_user_data=fake_user_data,
                                            directory_exists=True)

    def test_handle_python(self):
        fake_user_data = '^#!/usr/bin/env\spython\s'
        self._test_execute_user_data_script(fake_user_data=fake_user_data,
                                            directory_exists=True)

    def test_handle_shell(self):
        fake_user_data = '^#!'
        self._test_execute_user_data_script(fake_user_data=fake_user_data,
                                            directory_exists=True)

    def test_handle_powershell(self):
        fake_user_data = '^#ps1\s'
        self._test_execute_user_data_script(fake_user_data=fake_user_data,
                                            directory_exists=True)

    def test_handle_powershell_sysnative(self):
        fake_user_data = '#ps1_sysnative\s'
        self._test_execute_user_data_script(fake_user_data=fake_user_data,
                                            directory_exists=True)

    def test_handle_powershell_sysnative_no_sysnative(self):
        fake_user_data = '#ps1_sysnative\s'
        self._test_execute_user_data_script(fake_user_data=fake_user_data,
                                            directory_exists=False)
