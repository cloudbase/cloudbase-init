# Copyright 2015 Cloudbase Solutions Srl
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

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock


class TestPrivilege(unittest.TestCase):

    def setUp(self):
        self._win32process_mock = mock.MagicMock()
        self._win32security_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'win32process': self._win32process_mock,
             'win32security': self._win32security_mock})

        self._module_patcher.start()
        self.privilege_module = importlib.import_module(
            "cloudbaseinit.utils.windows.privilege")

    def tearDown(self):
        self._module_patcher.stop()

    def test_privilege_context_manager(self):
        fake_process = mock.MagicMock()
        fake_token = True
        LUID = 'fakeid'
        self._win32process_mock.GetCurrentProcess.return_value = fake_process
        self._win32security_mock.OpenProcessToken.return_value = fake_token
        self._win32security_mock.LookupPrivilegeValue.return_value = LUID
        privilege_enabled = [(LUID,
                             self._win32security_mock.SE_PRIVILEGE_ENABLED)]
        privilege_removed = [(LUID,
                             self._win32security_mock.SE_PRIVILEGE_REMOVED)]
        with self.privilege_module.acquire_privilege(mock.sentinel.privilege):

            self._win32security_mock.AdjustTokenPrivileges.assert_called_with(
                fake_token, False, privilege_enabled)

            self._win32security_mock.OpenProcessToken.assert_called_with(
                fake_process,
                self._win32security_mock.TOKEN_ADJUST_PRIVILEGES |
                self._win32security_mock.TOKEN_QUERY)

        self._win32security_mock.AdjustTokenPrivileges.assert_called_with(
            fake_token, False, privilege_removed)
