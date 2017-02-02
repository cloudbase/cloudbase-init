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

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.tests import testutils


class WindowsSecurityUtilsTests(unittest.TestCase):

    def setUp(self):
        self._moves_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'six.moves': self._moves_mock})

        self._module_patcher.start()
        self._winreg_mock = self._moves_mock.winreg

        self.security = importlib.import_module(
            "cloudbaseinit.utils.windows.security")
        self.security.WindowsError = testutils.FakeWindowsError

        self._security_utils = self.security.WindowsSecurityUtils()

    def tearDown(self):
        self._module_patcher.stop()

    def test_set_uac_remote_restrictions(self):
        fake_value = False
        self._security_utils.set_uac_remote_restrictions(
            enable=fake_value)

        self._winreg_mock.SetValueEx.assert_called_once_with(
            self._winreg_mock.CreateKey.return_value.__enter__(),
            self._security_utils._LATFP_VALUE_NAME, 0,
            self._winreg_mock.REG_DWORD, not fake_value)

        self._winreg_mock.CreateKey.assert_called_once_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            self._security_utils._SYSTEM_POLICIES_KEY)

    def _test_get_uac_remote_restrictions_win_error(self, ret_error=False):
        fake_errno = 2
        if ret_error:
            fake_errno = 0

        self._winreg_mock.OpenKey.side_effect = [
            self.security.WindowsError(fake_errno)]
        if ret_error:
            self.assertRaises(self.security.WindowsError,
                              self._security_utils.get_uac_remote_restrictions)
        else:
            response = self._security_utils.get_uac_remote_restrictions()
            self.assertTrue(response)

    def test_get_uac_remote_restrictions_win_error_ret_error(self):
        self._test_get_uac_remote_restrictions_win_error(ret_error=True)

    def test_get_uac_remote_restrictions_win_error(self):
        self._test_get_uac_remote_restrictions_win_error(ret_error=False)

    def test_get_uac_remote_restrictions_no_error(self):
        key = mock.MagicMock()
        fake_key_value = 0
        key.__enter__.return_value = fake_key_value
        fake_reg_type = mock.sentinel.fake_reg_type

        self._winreg_mock.OpenKey.return_value = key
        self._winreg_mock.QueryValueEx.return_value = (fake_key_value,
                                                       fake_reg_type)

        response = self._security_utils.get_uac_remote_restrictions()

        self._winreg_mock.QueryValueEx.assert_called_once_with(
            fake_key_value,
            self._security_utils._LATFP_VALUE_NAME)

        self._winreg_mock.OpenKey.assert_called_once_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            self._security_utils._SYSTEM_POLICIES_KEY)

        self.assertTrue(bool(response))
