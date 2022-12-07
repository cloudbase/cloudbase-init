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


import contextlib
import functools
import importlib
import os

import netaddr

try:
    import unittest.mock as mock
except ImportError:
    import mock
import six

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.tests import fake
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class WMIError(Exception):

    com_error = "fake data"


class TestWindowsUtils(testutils.CloudbaseInitTestBase):
    '''Tests for the windows utils class.'''

    _CONFIG_NAME = 'FakeConfig'
    _DESTINATION = '192.168.192.168'
    _GATEWAY = '10.7.1.1'
    _NETMASK = '255.255.255.0'
    _PASSWORD = 'Passw0rd'
    _SECTION = 'fake_section'
    _USERNAME = 'Admin'

    def setUp(self):
        self._pywintypes_mock = mock.MagicMock()
        self._pywintypes_mock.error = fake.FakeError
        self._pywintypes_mock.com_error = fake.FakeComError
        self._win32api_mock = mock.MagicMock()
        self._win32com_mock = mock.MagicMock()
        self._win32process_mock = mock.MagicMock()
        self._win32security_mock = mock.MagicMock()
        self._win32net_mock = mock.MagicMock()
        self._win32netcon_mock = mock.MagicMock()
        self._win32service_mock = mock.MagicMock()
        self._winerror_mock = mock.MagicMock()
        self._winerror_mock.ERROR_SERVICE_DOES_NOT_EXIST = 0x424
        self._mi_mock = mock.MagicMock()
        self._wmi_mock = mock.MagicMock()
        self._wmi_mock.x_wmi = WMIError
        self._moves_mock = mock.MagicMock()
        self._xmlrpc_client_mock = mock.MagicMock()
        self._ctypes_mock = mock.MagicMock()
        self._tzlocal_mock = mock.Mock()

        self._win32net_mock.error = Exception
        module_path = "cloudbaseinit.osutils.windows"

        _module_patcher = mock.patch.dict(
            'sys.modules',
            {'win32api': self._win32api_mock,
             'win32com': self._win32com_mock,
             'win32process': self._win32process_mock,
             'win32security': self._win32security_mock,
             'win32net': self._win32net_mock,
             'win32netcon': self._win32netcon_mock,
             'win32service': self._win32service_mock,
             'winerror': self._winerror_mock,
             'mi': self._mi_mock,
             'wmi': self._wmi_mock,
             'six.moves': self._moves_mock,
             'six.moves.xmlrpc_client': self._xmlrpc_client_mock,
             'ctypes': self._ctypes_mock,
             'pywintypes': self._pywintypes_mock,
             'tzlocal': self._tzlocal_mock,
             'winioctlcon': mock.MagicMock()})
        _module_patcher.start()
        self.addCleanup(_module_patcher.stop)

        exception.ctypes.GetLastError = mock.MagicMock()
        exception.ctypes.FormatError = mock.MagicMock()
        with mock.patch("cloudbaseinit.utils.windows.disk.GUID"):
            self.windows_utils = importlib.import_module(module_path)

        self._winreg_mock = self._moves_mock.winreg
        self._windll_mock = self._ctypes_mock.windll
        self._wintypes_mock = self._ctypes_mock.wintypes
        self._client_mock = self._win32com_mock.client
        self.windows_utils.WindowsError = mock.MagicMock()

        self._winutils = self.windows_utils.WindowsUtils()
        self._kernel32 = self._windll_mock.kernel32
        self._iphlpapi = self._windll_mock.iphlpapi
        self._ntdll = self._windll_mock.ntdll

        self.snatcher = testutils.LogSnatcher(module_path)

    @mock.patch('cloudbaseinit.osutils.windows.privilege')
    def _test_reboot(self, mock_privilege_module, ret_value,
                     expected_ret_value=None):
        mock_privilege_module.acquire_privilege = mock.MagicMock()
        advapi32 = self._windll_mock.advapi32
        advapi32.InitiateSystemShutdownExW = mock.MagicMock(
            return_value=ret_value)

        if not ret_value:
            with self.assert_raises_windows_message(
                    "Reboot failed: %r", expected_ret_value):
                self._winutils.reboot()
        else:
            self._winutils.reboot()

            advapi32.InitiateSystemShutdownExW.assert_called_with(
                0,
                "Cloudbase-Init reboot",
                0, True, True, 0)
        mock_privilege_module.acquire_privilege.assert_called_once_with(
            self._win32security_mock.SE_SHUTDOWN_NAME)

    def test_reboot(self):
        self._test_reboot(ret_value=True)

    def test_reboot_failed(self):
        self._test_reboot(ret_value=None, expected_ret_value=100)

    def _test_get_user_info(self, exc=None):
        userget_mock = self._win32net_mock.NetUserGetInfo
        level = mock.Mock()
        ret = mock.Mock()
        if exc:
            userget_mock.side_effect = [exc]
            error_class = (
                exception.ItemNotFoundException if
                exc.args[0] == self._winutils.NERR_UserNotFound else
                exception.CloudbaseInitException)
            with self.assertRaises(error_class):
                self._winutils._get_user_info(self._USERNAME, level)
            return
        userget_mock.return_value = ret
        response = self._winutils._get_user_info(self._USERNAME, level)
        userget_mock.assert_called_once_with(None, self._USERNAME, level)
        self.assertEqual(ret, response)

    def test_get_user_info(self):
        self._test_get_user_info()

    def test_get_user_info_not_found(self):
        exc = self._win32net_mock.error(self._winutils.NERR_UserNotFound,
                                        *([mock.Mock()] * 2))
        self._test_get_user_info(exc=exc)

    def test_get_user_info_failed(self):
        exc = self._win32net_mock.error(*([mock.Mock()] * 3))
        self._test_get_user_info(exc=exc)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_user_info')
    def _test_set_user_password(self, mock_get_user_info,
                                expire=False, fail=False):
        user_info = mock.MagicMock()
        mock_get_user_info.return_value = user_info
        user_info["password"] = self._PASSWORD
        if expire:
            user_info["flags"] &= \
                ~self._win32netcon_mock.UF_DONT_EXPIRE_PASSWD
        else:
            user_info["flags"] |= \
                self._win32netcon_mock.UF_DONT_EXPIRE_PASSWD
        if fail:
            self._win32net_mock.NetUserSetInfo.side_effect = [
                self._win32net_mock.error(*([mock.Mock()] * 3))]
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.set_user_password(self._USERNAME,
                                                 self._PASSWORD)
            return
        self._winutils.set_user_password(self._USERNAME, self._PASSWORD,
                                         password_expires=expire)
        mock_get_user_info.assert_called_once_with(self._USERNAME, 1)
        self._win32net_mock.NetUserSetInfo.assert_called_once_with(
            None, self._USERNAME, 1, user_info)

    def test_set_user_password(self):
        self._test_set_user_password()

    def test_set_user_password_expire(self):
        self._test_set_user_password(expire=True)

    def test_set_user_password_fail(self):
        self._test_set_user_password(fail=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_user_info')
    def _test_change_password_next_logon(self, mock_get_user_info,
                                         fail=False):
        user_info = mock.MagicMock()
        mock_get_user_info.return_value = user_info
        user_info["flags"] &= ~self._win32netcon_mock.UF_DONT_EXPIRE_PASSWD
        user_info["password_expired"] = 1
        if fail:
            self._win32net_mock.NetUserSetInfo.side_effect = [
                self._win32net_mock.error(*([mock.Mock()] * 3))]
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.change_password_next_logon(self._USERNAME)
            return
        self._winutils.change_password_next_logon(self._USERNAME)
        self._win32net_mock.NetUserSetInfo.assert_called_once_with(
            None, self._USERNAME, 4, user_info)

    def test_change_password_next_logon(self):
        self._test_change_password_next_logon()

    def test_change_password_next_logon_fail(self):
        self._test_change_password_next_logon(fail=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_user_info')
    def _test_user_exists(self, mock_get_user_info, exists):
        if not exists:
            mock_get_user_info.side_effect = [exception.ItemNotFoundException]
            response = self._winutils.user_exists(self._USERNAME)
            self.assertEqual(False, response)
            return
        response = self._winutils.user_exists(self._USERNAME)
        mock_get_user_info.assert_called_once_with(self._USERNAME, 1)
        self.assertEqual(True, response)

    def test_user_exists(self):
        self._test_user_exists(exists=True)

    def test_user_does_not_exist(self):
        self._test_user_exists(exists=False)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_group_info')
    def _test_group_exists(self, mock_get_group_info, exists):
        fake_group_name = 'fake_group'
        if not exists:
            mock_get_group_info.side_effect = [exception.ItemNotFoundException]
            response = self._winutils.group_exists(fake_group_name)
            self.assertEqual(False, response)
            return
        response = self._winutils.group_exists(fake_group_name)
        mock_get_group_info.assert_called_once_with(fake_group_name, 1)
        self.assertEqual(True, response)

    def test_group_exists(self):
        self._test_group_exists(exists=True)

    def test_group_does_not_exist(self):
        self._test_group_exists(exists=False)

    def _test_create_group(self, fail=False):
        fake_group = "fake_group"
        group_info = {"name": fake_group}

        if fail:
            self._win32net_mock.NetLocalGroupAdd.side_effect = [
                self._win32net_mock.error(*([mock.Mock()] * 3))]
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.create_group(fake_group)
            return
        self._winutils.create_group(fake_group)
        self._win32net_mock.NetLocalGroupAdd.assert_called_once_with(
            None, 0, group_info)

    def test_create_group(self):
        self._test_create_group()

    def test_create_group_fail(self):
        self._test_create_group(True)

    def test_sanitize_shell_input(self):
        unsanitised = ' " '
        response = self._winutils.sanitize_shell_input(unsanitised)
        sanitised = ' \\" '
        self.assertEqual(sanitised, response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                '_get_cch_referenced_domain_name')
    def _test_get_user_sid_and_domain(self, mock_cch_referenced,
                                      ret_val, last_error=None):
        cbSid = mock.Mock()
        sid = mock.Mock()
        size = 1024
        cchReferencedDomainName = mock.Mock()
        domainName = mock.Mock()
        sidNameUse = mock.Mock()
        advapi32 = self._windll_mock.advapi32
        mock_cch_referenced.return_value = cchReferencedDomainName

        self._ctypes_mock.create_string_buffer.return_value = sid
        self._ctypes_mock.sizeof.return_value = size
        self._ctypes_mock.create_unicode_buffer.return_value = domainName

        advapi32.LookupAccountNameW.return_value = ret_val

        if ret_val is None:
            with self.assert_raises_windows_message(
                    "Cannot get user SID: %r",
                    last_error):
                self._winutils._get_user_sid_and_domain(
                    self._USERNAME)
        else:
            response = self._winutils._get_user_sid_and_domain(self._USERNAME)

            advapi32.LookupAccountNameW.assert_called_with(
                0, six.text_type(self._USERNAME), sid,
                self._ctypes_mock.byref(cbSid), domainName,
                self._ctypes_mock.byref(cchReferencedDomainName),
                self._ctypes_mock.byref(sidNameUse))
            self.assertEqual((sid, domainName.value), response)
        mock_cch_referenced.assert_called_once_with(
            self._ctypes_mock.create_unicode_buffer.return_value)

    def test_get_cch_referenced_domain_name(self):
        self._ctypes_mock.sizeof.side_effect = [42, 24]

        result = self._winutils._get_cch_referenced_domain_name(
            mock.sentinel.domain_name)

        self._wintypes_mock.DWORD.assert_called_once_with(42 // 24)
        self.assertEqual(result, self._wintypes_mock.DWORD.return_value)

    def test_get_user_sid_and_domain(self):
        fake_obj = mock.Mock()
        self._test_get_user_sid_and_domain(ret_val=fake_obj)

    def test_get_user_sid_and_domain_no_return_value(self):
        self._test_get_user_sid_and_domain(ret_val=None, last_error=100)

    @mock.patch('cloudbaseinit.osutils.windows'
                '.Win32_LOCALGROUP_MEMBERS_INFO_3')
    def _test_add_user_to_local_group(self,
                                      mock_Win32_LOCALGROUP_MEMBERS_INFO_3,
                                      ret_value):
        lmi = mock_Win32_LOCALGROUP_MEMBERS_INFO_3()
        group_name = 'Admins'
        netapi32 = self._windll_mock.netapi32

        netapi32.NetLocalGroupAddMembers.return_value = ret_value

        is_in_alias = ret_value != self._winutils.ERROR_MEMBER_IN_ALIAS

        if ret_value is not 0 and is_in_alias:
            self.assertRaises(
                exception.CloudbaseInitException,
                self._winutils.add_user_to_local_group,
                self._USERNAME, group_name)
        else:
            self._winutils.add_user_to_local_group(self._USERNAME,
                                                   group_name)

            netapi32.NetLocalGroupAddMembers.assert_called_with(
                0, six.text_type(group_name), 3,
                self._ctypes_mock.pointer.return_value, 1)

            self._ctypes_mock.pointer.assert_called_once_with(lmi)
            self.assertEqual(lmi.lgrmi3_domainandname,
                             six.text_type(self._USERNAME))

    def test_add_user_to_local_group_no_error(self):
        self._test_add_user_to_local_group(ret_value=0)

    def test_add_user_to_local_group_not_found(self):
        self._test_add_user_to_local_group(
            ret_value=self._winutils.NERR_GroupNotFound)

    def test_add_user_to_local_group_access_denied(self):
        self._test_add_user_to_local_group(
            ret_value=self._winutils.ERROR_ACCESS_DENIED)

    def test_add_user_to_local_group_no_member(self):
        self._test_add_user_to_local_group(
            ret_value=self._winutils.ERROR_NO_SUCH_MEMBER)

    def test_add_user_to_local_group_member_in_alias(self):
        self._test_add_user_to_local_group(
            ret_value=self._winutils.ERROR_MEMBER_IN_ALIAS)

    def test_add_user_to_local_group_invalid_member(self):
        self._test_add_user_to_local_group(
            ret_value=self._winutils.ERROR_INVALID_MEMBER)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_user_info')
    def _test_get_user_sid(self, mock_get_user_info, fail):
        if fail:
            mock_get_user_info.side_effect = [exception.ItemNotFoundException]
            response = self._winutils.get_user_sid(self._USERNAME)
            self.assertEqual(None, response)
            return
        user_info = mock.MagicMock()
        mock_get_user_info.return_value = user_info
        response = self._winutils.get_user_sid(self._USERNAME)
        mock_get_user_info.assert_called_once_with(self._USERNAME, 4)
        self.assertEqual(response, str(user_info["user_sid"])[6:])

    def test_get_user_sid(self):
        self._test_get_user_sid(fail=False)

    def test_get_user_sid_fail(self):
        self._test_get_user_sid(fail=True)

    def _test_create_user(self, expire=False, fail=False):
        user_info = {
            "name": self._USERNAME,
            "password": self._PASSWORD,
            "priv": self._win32netcon_mock.USER_PRIV_USER,
            "flags": (self._win32netcon_mock.UF_NORMAL_ACCOUNT |
                      self._win32netcon_mock.UF_SCRIPT)
        }
        if not expire:
            user_info["flags"] |= self._win32netcon_mock.UF_DONT_EXPIRE_PASSWD

        if fail:
            self._win32net_mock.NetUserAdd.side_effect = [
                self._win32net_mock.error(*([mock.Mock()] * 3))]
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.create_user(self._USERNAME,
                                           self._PASSWORD)
            return
        self._winutils.create_user(self._USERNAME, self._PASSWORD,
                                   password_expires=expire)
        self._win32net_mock.NetUserAdd.assert_called_once_with(
            None, 1, user_info)

    def test_create_user(self):
        self._test_create_user()

    def test_create_user_expire(self):
        self._test_create_user(expire=True)

    def test_create_user_fail(self):
        self._test_create_user(fail=True)

    @mock.patch('cloudbaseinit.osutils.windows.Win32_PROFILEINFO')
    @mock.patch('time.sleep')
    def _test_create_user_logon_session(self, mock_time_sleep,
                                        mock_Win32_PROFILEINFO, logon,
                                        loaduser, load_profile=True,
                                        last_error=None):
        self._wintypes_mock.HANDLE = mock.MagicMock()
        pi = self.windows_utils.Win32_PROFILEINFO()
        advapi32 = self._windll_mock.advapi32
        userenv = self._windll_mock.userenv
        kernel32 = self._windll_mock.kernel32

        advapi32.LogonUserW.return_value = logon

        if not logon:
            with self.assert_raises_windows_message(
                    "User logon failed: %r", last_error):
                self._winutils.create_user_logon_session(
                    self._USERNAME, self._PASSWORD, domain='.',
                    load_profile=load_profile)

        elif load_profile and not loaduser:
            userenv.LoadUserProfileW.return_value = None
            kernel32.CloseHandle.return_value = None
            with self.assert_raises_windows_message(
                    "Cannot load user profile: %r", last_error,
                    get_last_error_called_times=4,
                    format_error_called_times=4):
                self._winutils.create_user_logon_session(
                    self._USERNAME, self._PASSWORD, domain='.',
                    load_profile=load_profile)

            userenv.LoadUserProfileW.assert_called_with(
                self._wintypes_mock.HANDLE.return_value,
                self._ctypes_mock.byref.return_value)
            self._ctypes_mock.byref.assert_called_with(pi)

            kernel32.CloseHandle.assert_called_with(
                self._wintypes_mock.HANDLE.return_value)

        elif not load_profile:
            response = self._winutils.create_user_logon_session(
                self._USERNAME, self._PASSWORD, domain='.',
                load_profile=load_profile)
            self.assertTrue(response is not None)
        else:
            size = 1024
            self._ctypes_mock.sizeof.return_value = size

            mock_Win32_PROFILEINFO.return_value = loaduser

            response = self._winutils.create_user_logon_session(
                self._USERNAME, self._PASSWORD, domain='.',
                load_profile=load_profile)

            userenv.LoadUserProfileW.assert_called_with(
                self._wintypes_mock.HANDLE.return_value,
                self._ctypes_mock.byref.return_value)
            self.assertTrue(response is not None)

    def test_create_user_logon_session_fail_load_false(self):
        self._test_create_user_logon_session(logon=0, loaduser=0,
                                             load_profile=True,
                                             last_error=100)

    def test_create_user_logon_session_fail_load_true(self):
        self._test_create_user_logon_session(logon=0, loaduser=0,
                                             load_profile=False,
                                             last_error=100)

    def test_create_user_logon_session_load_true(self):
        m = mock.Mock()
        n = mock.Mock()
        self._test_create_user_logon_session(logon=m, loaduser=n,
                                             load_profile=True)

    def test_create_user_logon_session_load_false(self):
        m = mock.Mock()
        n = mock.Mock()
        self._test_create_user_logon_session(logon=m, loaduser=n,
                                             load_profile=False)

    def test_create_user_logon_session_no_load_true(self):
        m = mock.Mock()
        self._test_create_user_logon_session(logon=m, loaduser=None,
                                             load_profile=True,
                                             last_error=100)

    def test_create_user_logon_session_no_load_false(self):
        m = mock.Mock()
        self._test_create_user_logon_session(logon=m, loaduser=None,
                                             load_profile=False,
                                             last_error=100)

    def test_close_user_logon_session(self):
        token = mock.Mock()
        self._windll_mock.kernel32.CloseHandle = mock.MagicMock()

        self._winutils.close_user_logon_session(token)

        self._windll_mock.kernel32.CloseHandle.assert_called_with(token)

    @mock.patch('ctypes.windll.kernel32.SetComputerNameExW')
    def _test_set_host_name(self, mock_SetComputerNameExW, ret_value,
                            last_error=None):
        mock_SetComputerNameExW.return_value = ret_value

        if not ret_value:
            with self.assert_raises_windows_message(
                    "Cannot set host name: %r", last_error):
                self._winutils.set_host_name('fake name')
        else:
            self.assertTrue(self._winutils.set_host_name('fake name'))

        mock_SetComputerNameExW.assert_called_with(
            self._winutils.ComputerNamePhysicalDnsHostname,
            six.text_type('fake name'))

    def test_set_host_name(self):
        self._test_set_host_name(ret_value='fake response')

    def test_set_host_exception(self):
        self._test_set_host_name(ret_value=None, last_error=100)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_user_sid')
    def _test_get_user_home(self, user_sid, mock_get_user_sid):
        mock_get_user_sid.return_value = user_sid

        with self.snatcher:
            response = self._winutils.get_user_home(self._USERNAME)

        if user_sid:
            mock_get_user_sid.assert_called_with(self._USERNAME)
            self._winreg_mock.OpenKey.assert_called_with(
                self._winreg_mock.HKEY_LOCAL_MACHINE,
                'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\'
                'ProfileList\\%s' % mock_get_user_sid())
            self.assertTrue(response is not None)
            self._winreg_mock.QueryValueEx.assert_called_with(
                self._winreg_mock.OpenKey.return_value.__enter__.return_value,
                'ProfileImagePath')
        else:
            self.assertEqual(
                ["Home directory not found for user %r" % self._USERNAME],
                self.snatcher.output)
            self.assertTrue(response is None)

    def test_get_user_home(self):
        user = mock.MagicMock()
        self._test_get_user_home(user)

    def test_get_user_home_fail(self):
        self._test_get_user_home(None)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_os_version')
    def _test_get_network_adapters(self, is_xp_2003, mock_check_os_version):
        conn = self._wmi_mock.WMI
        mock_response = mock.MagicMock()
        conn.return_value.query.return_value = [mock_response]

        mock_check_os_version.return_value = not is_xp_2003

        wql = ('SELECT * FROM Win32_NetworkAdapter WHERE '
               'AdapterTypeId = 0 AND MACAddress IS NOT NULL')

        if not is_xp_2003:
            wql += ' AND PhysicalAdapter = True'

        response = self._winutils.get_network_adapters()
        conn.return_value.query.assert_called_with(wql)
        self.assertEqual(
            [(mock_response.NetConnectionID, mock_response.MACAddress)],
            response)

    def test_get_network_adapters(self):
        self._test_get_network_adapters(False)

    def test_get_network_adapters_xp_2003(self):
        self._test_get_network_adapters(True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_network_adapter')
    def _test_enable_network_adapter(self, mock_get_network_adapter, enabled):
        self._winutils.enable_network_adapter(
            mock.sentinel.adapter_name, enabled)

        mock_get_network_adapter.assert_called_once_with(
            mock.sentinel.adapter_name)

        adapter = mock_get_network_adapter.return_value
        if enabled:
            adapter.Enable.assert_called_once_with()
        else:
            adapter.Disable.assert_called_once_with()

    def test_enable_network_adapter(self):
        self._test_enable_network_adapter(enabled=True)

    def test_disable_network_adapter(self):
        self._test_enable_network_adapter(enabled=False)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_os_version')
    def _test_set_static_network_config(self, mock_check_os_version,
                                        adapter=True, static_val=(0,),
                                        gateway_val=(0,), dns_val=(0,),
                                        legacy=False, ipv6=False):
        mock_check_os_version.return_value = not legacy
        if legacy:
            self._test_set_static_network_config_legacy(
                adapter, static_val, gateway_val, dns_val)
        else:
            self._test_set_static_network_config_new(ipv6=ipv6)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._fix_network_adapter_dhcp')
    def _test_set_static_network_config_new(self,
                                            mock_fix_network_adapter_dhcp,
                                            ipv6):
        conn = self._wmi_mock.WMI.return_value
        if ipv6:
            mock.sentinel.address = "2001:db8::3"
            mock.sentinel.prefix_len_or_netmask = 64
        else:
            mock.sentinel.address = "10.10.10.10"
            mock.sentinel.prefix_len_or_netmask = "255.255.255.0"

        adapter = mock.Mock()
        adapter.GUID = mock.sentinel.adapter_guid
        conn.Win32_NetworkAdapter.return_value = [adapter]

        if netaddr.valid_ipv6(mock.sentinel.address):
            family = self.windows_utils.AF_INET6
        else:
            family = self.windows_utils.AF_INET

        existing_adapter = mock.Mock()
        existing_adapter.IPAddress = mock.sentinel.address
        conn.MSFT_NetIPAddress.return_value = [existing_adapter]

        existing_route = mock.Mock()
        existing_route.DestinationPrefix = "0.0.0.0"
        conn.MSFT_NetRoute.return_value = [existing_route]

        dns_client = mock.Mock()
        conn.MSFT_DnsClientServerAddress.return_value = [dns_client]

        self._winutils.set_static_network_config(
            mock.sentinel.nick_name, mock.sentinel.address,
            mock.sentinel.prefix_len_or_netmask, mock.sentinel.gateway,
            [mock.sentinel.dns])

        mock_fix_network_adapter_dhcp.assert_called_once_with(
            mock.sentinel.nick_name, False, family)

        conn.MSFT_NetIPAddress.assert_called_once_with(
            AddressFamily=family, InterfaceAlias=mock.sentinel.nick_name)
        existing_adapter.Delete_.assert_called_once_with()

        conn.MSFT_NetRoute.assert_called_once_with(
            AddressFamily=family, InterfaceAlias=mock.sentinel.nick_name)
        existing_route.Delete_.assert_called_once_with()

        ip_network = netaddr.IPNetwork(
            u"%s/%s" % (
                mock.sentinel.address, mock.sentinel.prefix_len_or_netmask))
        prefix_len = ip_network.prefixlen

        conn.MSFT_NetIPAddress.create.assert_called_once_with(
            AddressFamily=family, InterfaceAlias=mock.sentinel.nick_name,
            IPAddress=mock.sentinel.address, PrefixLength=prefix_len,
            DefaultGateway=mock.sentinel.gateway)

        custom_options = [{
            u'name': u'ServerAddresses',
            u'value_type': self._mi_mock.MI_ARRAY | self._mi_mock.MI_STRING,
            u'value': [mock.sentinel.dns]
        }]
        operation_options = {u'custom_options': custom_options}
        dns_client.put.assert_called_once_with(
            operation_options=operation_options)

    def _test_set_static_network_config_legacy(self, adapter, static_val,
                                               gateway_val, dns_val):
        conn = self._wmi_mock.WMI.return_value
        nic_name = 'fake NIC'
        address = '10.10.10.10'
        dns_list = ['8.8.8.8']
        set_static_call = functools.partial(
            self._winutils.set_static_network_config,
            nic_name, address, self._NETMASK, self._GATEWAY, dns_list)

        if adapter:
            adapter = mock.MagicMock()
        else:
            self.assertRaises(
                exception.CloudbaseInitException,
                set_static_call
            )
            return

        expected_log = []
        for (ret_val,), msg in ((static_val, "Setting static IP address"),
                                (gateway_val, "Setting static gateways"),
                                (dns_val, "Setting static DNS servers")):
            if ret_val in (0, 1):
                expected_log.append(msg)

        conn.Win32_NetworkAdapter.return_value = [adapter]
        adapter_config = adapter.associators.return_value[0]
        adapter_config.EnableStatic.return_value = static_val
        adapter_config.SetGateways.return_value = gateway_val
        adapter_config.SetDNSServerSearchOrder.return_value = dns_val
        adapter.__len__.return_value = 1
        if static_val[0] > 1 or gateway_val[0] > 1 or dns_val[0] > 1:
            self.assertRaises(
                exception.CloudbaseInitException,
                set_static_call)
        else:
            with self.snatcher:
                response = set_static_call()
            if static_val[0] or gateway_val[0] or dns_val[0]:
                self.assertTrue(response)
            else:
                self.assertFalse(response)
            self.assertEqual(expected_log, self.snatcher.output)

            conn.Win32_NetworkAdapter.assert_called_once_with(
                NetConnectionID=nic_name)
            adapter.associators.assert_called_with(
                wmi_result_class='Win32_NetworkAdapterConfiguration')
            adapter_config.EnableStatic.assert_called_with(
                [address], [self._NETMASK])
            adapter_config.SetGateways.assert_called_with(
                [self._GATEWAY], [1])
            adapter_config.SetDNSServerSearchOrder.assert_called_with(
                dns_list)

    def test_set_static_network_config_legacy(self):
        ret_val1 = (1,)
        ret_val2 = (1,)
        ret_val3 = (0,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2,
                                             dns_val=ret_val3,
                                             legacy=True)

    def test_set_static_network_config_legacy_query_fail(self):
        self._test_set_static_network_config(adapter=False, legacy=True)

    def test_set_static_network_config_legacy_cannot_set_ip(self):
        ret_val1 = (2,)
        self._test_set_static_network_config(static_val=ret_val1, legacy=True)

    def test_set_static_network_config_legacy_cannot_set_gateway(self):
        ret_val1 = (1,)
        ret_val2 = (2,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2,
                                             legacy=True)

    def test_set_static_network_config_legacy_cannot_set_DNS(self):
        ret_val1 = (1,)
        ret_val2 = (1,)
        ret_val3 = (2,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2,
                                             dns_val=ret_val3,
                                             legacy=True)

    def test_set_static_network_config_legacy_no_reboot(self):
        ret_val1 = (0,)
        ret_val2 = (0,)
        ret_val3 = (0,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2,
                                             dns_val=ret_val3,
                                             legacy=True)

    def test_set_static_network_config_ipv4(self):
        self._test_set_static_network_config(ipv6=False)

    def test_set_static_network_config_ipv6(self):
        self._test_set_static_network_config(ipv6=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.execute_process')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_system_dir')
    def _test_rename_network_adapter(self, should_fail, mock_get_system_dir,
                                     mock_execute_process):
        base_dir = "fake path"
        old_name = "fake_old"
        new_name = "fake_new"
        mock_get_system_dir.return_value = base_dir
        ret_val = 1 if should_fail else 0
        mock_execute_process.return_value = (None, None, ret_val)

        if should_fail:
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.rename_network_adapter(old_name, new_name)
        else:
            self._winutils.rename_network_adapter(old_name, new_name)

        mock_get_system_dir.assert_called_once_with()
        args = [os.path.join(base_dir, "netsh.exe"), "interface", "set",
                "interface", 'name=%s' % old_name, 'newname=%s' % new_name]
        mock_execute_process.assert_called_once_with(args, shell=False)

    def _test_get_config_key_name(self, section):
        response = self._winutils._get_config_key_name(section)
        if section:
            self.assertEqual(self._winutils._config_key + section + '\\',
                             response)
        else:
            self.assertEqual(self._winutils._config_key, response)

    def test_get_config_key_name_with_section(self):
        self._test_get_config_key_name(self._SECTION)

    def test_get_config_key_name_no_section(self):
        self._test_get_config_key_name(None)

    def test_rename_network_adapter(self):
        self._test_rename_network_adapter(False)

    def test_rename_network_adapter_fail(self):
        self._test_rename_network_adapter(True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_config_key_name')
    def _test_set_config_value(self, value, mock_get_config_key_name):
        key_name = (self._winutils._config_key + self._SECTION + '\\' +
                    self._CONFIG_NAME)
        mock_get_config_key_name.return_value = key_name

        self._winutils.set_config_value(self._CONFIG_NAME, value,
                                        self._SECTION)

        key = self._winreg_mock.CreateKey.return_value.__enter__.return_value

        self._winreg_mock.CreateKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE, key_name)
        mock_get_config_key_name.assert_called_with(self._SECTION)

        if type(value) == int:
            self._winreg_mock.SetValueEx.assert_called_with(
                key, self._CONFIG_NAME, 0, self._winreg_mock.REG_DWORD, value)

        else:
            self._winreg_mock.SetValueEx.assert_called_with(
                key, self._CONFIG_NAME, 0, self._winreg_mock.REG_SZ, value)

    def test_set_config_value_int(self):
        self._test_set_config_value(1)

    def test_set_config_value_not_int(self):
        self._test_set_config_value('1')

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_config_key_name')
    def _test_get_config_value(self, value, mock_get_config_key_name):
        key_name = self._winutils._config_key + self._SECTION + '\\'
        key_name += self._CONFIG_NAME

        if type(value) == int:
            regtype = self._winreg_mock.REG_DWORD
        else:
            regtype = self._winreg_mock.REG_SZ

        self._winreg_mock.QueryValueEx.return_value = (value, regtype)

        if value is None:
            mock_get_config_key_name.side_effect = [
                self.windows_utils.WindowsError]
            response = self._winutils.get_config_value(self._CONFIG_NAME,
                                                       self._SECTION)
            self.assertEqual(None, response)

        else:
            mock_get_config_key_name.return_value = key_name

            response = self._winutils.get_config_value(self._CONFIG_NAME,
                                                       self._SECTION)

            self._winreg_mock.OpenKey.assert_called_with(
                self._winreg_mock.HKEY_LOCAL_MACHINE, key_name)
            mock_get_config_key_name.assert_called_with(self._SECTION)
            self._winreg_mock.QueryValueEx.assert_called_with(
                self._winreg_mock.OpenKey().__enter__(), self._CONFIG_NAME)
            self.assertEqual(value, response)

    def test_get_config_value_type_int(self):
        self._test_get_config_value(1)

    def test_get_config_value_type_str(self):
        self._test_get_config_value('fake')

    def test_get_config_value_type_error(self):
        self._test_get_config_value(None)

    @mock.patch('time.sleep')
    def _test_wait_for_boot_completion(self, _, ret_vals=None):
        self._winreg_mock.QueryValueEx.side_effect = ret_vals

        with self.snatcher:
            self._winutils.wait_for_boot_completion()

        key = self._winreg_mock.OpenKey.return_value.__enter__.return_value
        self._winreg_mock.OpenKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            "SYSTEM\\Setup\\Status\\SysprepStatus", 0,
            self._winreg_mock.KEY_READ)

        expected_log = []
        for gen_states in ret_vals:
            gen_state = gen_states[0]
            if gen_state == 7:
                break
            expected_log.append('Waiting for sysprep completion. '
                                'GeneralizationState: %d' % gen_state)
        self._winreg_mock.QueryValueEx.assert_called_with(
            key, "GeneralizationState")
        self.assertEqual(expected_log, self.snatcher.output)

    def test_wait_for_boot_completion(self):
        ret_vals = [[7]]
        self._test_wait_for_boot_completion(ret_vals=ret_vals)

    def test_wait_for_boot_completion_wait(self):
        ret_vals = [[1], [7]]
        self._test_wait_for_boot_completion(ret_vals=ret_vals)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_check_service(self, mock_get_service_handle):
        mock_context_manager = mock.MagicMock()
        mock_context_manager.__enter__.return_value = "fake name"
        mock_get_service_handle.return_value = mock_context_manager

        self.assertTrue(self._winutils.check_service_exists("fake_name"))

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_check_service_fail(self, mock_get_service_handle):
        exc = self._pywintypes_mock.error("ERROR_SERVICE_DOES_NOT_EXIST")
        exc.winerror = self._winerror_mock.ERROR_SERVICE_DOES_NOT_EXIST

        exc2 = self._pywintypes_mock.error("NOT ERROR_SERVICE_DOES_NOT_EXIST")
        exc2.winerror = None

        mock_context_manager = mock.MagicMock()
        mock_context_manager.__enter__.side_effect = [exc, exc2]
        mock_get_service_handle.return_value = mock_context_manager

        self.assertFalse(self._winutils.check_service_exists("fake_name"))
        self.assertRaises(self._pywintypes_mock.error,
                          self._winutils.check_service_exists,
                          "fake_name")

    def test_get_service_handle(self):
        open_scm = self._win32service_mock.OpenSCManager
        open_scm.return_value = mock.sentinel.hscm
        open_service = self._win32service_mock.OpenService
        open_service.return_value = mock.sentinel.hs
        close_service = self._win32service_mock.CloseServiceHandle
        args = ("fake_name", mock.sentinel.service_access,
                mock.sentinel.scm_access)

        with self._winutils._get_service_handle(*args) as hs:
            self.assertIs(hs, mock.sentinel.hs)

        open_scm.assert_called_with(None, None, mock.sentinel.scm_access)
        open_service.assert_called_with(mock.sentinel.hscm, "fake_name",
                                        mock.sentinel.service_access)
        close_service.assert_has_calls([mock.call(mock.sentinel.hs),
                                        mock.call(mock.sentinel.hscm)])

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_control_manager')
    def test_create_service(self, mock_get_service_control_manager):
        mock_hs = mock.MagicMock()
        mock_service_name = "fake name"
        mock_start_mode = "Automatic"
        mock_display_name = mock.sentinel.mock_display_name
        mock_path = mock.sentinel.path
        mock_get_service_control_manager.return_value = mock_hs
        with self.snatcher:
            self._winutils.create_service(mock_service_name,
                                          mock_display_name,
                                          mock_path,
                                          mock_start_mode)
            self.assertEqual(["Creating service fake name"],
                             self.snatcher.output)

        mock_get_service_control_manager.assert_called_once_with(
            scm_access=self._win32service_mock.SC_MANAGER_CREATE_SERVICE)
        self._win32service_mock.CreateService.assert_called_once_with(
            mock_hs.__enter__(), mock_service_name, mock_display_name,
            self._win32service_mock.SERVICE_ALL_ACCESS,
            self._win32service_mock.SERVICE_WIN32_OWN_PROCESS,
            self._win32service_mock.SERVICE_AUTO_START,
            self._win32service_mock.SERVICE_ERROR_NORMAL,
            mock_path, None, False, None, None, None)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_delete_service(self, mock_get_service_handle):
        mock_hs = mock.MagicMock()
        fake_service_name = "fake name"
        mock_get_service_handle.return_value = mock_hs
        with self.snatcher:
            self._winutils.delete_service(fake_service_name)
            self.assertEqual(["Deleting service fake name"],
                             self.snatcher.output)
        self._win32service_mock.DeleteService.assert_called_once_with(
            mock_hs.__enter__())
        mock_get_service_handle.assert_called_once_with(
            fake_service_name, self._win32service_mock.SERVICE_ALL_ACCESS)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_set_service_credentials(self, mock_get_service):
        self._win32service_mock.SERVICE_CHANGE_CONFIG = mock.sentinel.change
        self._win32service_mock.SERVICE_NO_CHANGE = mock.sentinel.no_change
        mock_change_service = self._win32service_mock.ChangeServiceConfig
        mock_context_manager = mock.MagicMock()
        mock_context_manager.__enter__.return_value = mock.sentinel.hs
        mock_get_service.return_value = mock_context_manager

        self._winutils.set_service_credentials(
            mock.sentinel.service, mock.sentinel.user, mock.sentinel.password)

        mock_get_service.assert_called_with(mock.sentinel.service,
                                            mock.sentinel.change)
        mock_change_service.assert_called_with(
            mock.sentinel.hs, mock.sentinel.no_change, mock.sentinel.no_change,
            mock.sentinel.no_change, None, None, False, None,
            mock.sentinel.user, mock.sentinel.password, None)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_get_service_username(self, mock_get_service):
        mock_context_manager = mock.MagicMock()
        mock_context_manager.__enter__.return_value = mock.sentinel.hs
        mock_get_service.return_value = mock_context_manager
        mock_query_service = self._win32service_mock.QueryServiceConfig
        mock_query_service.return_value = [mock.sentinel.value] * 8

        response = self._winutils.get_service_username(mock.sentinel.service)

        mock_get_service.assert_called_with(mock.sentinel.service)
        mock_query_service.assert_called_with(mock.sentinel.hs)
        self.assertIs(response, mock.sentinel.value)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.set_service_credentials')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.set_user_password')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.generate_random_password')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_service_username')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_service_exists')
    def _test_reset_service_password(self, mock_service_exists,
                                     mock_get_username, mock_generate_password,
                                     mock_set_password, mock_set_credentials,
                                     service_exists, service_username):
        mock_service_exists.return_value = service_exists
        mock_get_username.return_value = service_username
        mock_generate_password.return_value = mock.sentinel.password

        with self.snatcher:
            response = self._winutils.reset_service_password()

        if not service_exists:
            self.assertEqual(
                ["Service does not exist: %s" % self._winutils._service_name],
                self.snatcher.output)
            self.assertFalse(response)
            return

        if "\\" not in service_username:
            self.assertEqual(
                ["Skipping password reset, service running as a built-in "
                 "account: %s" % service_username], self.snatcher.output)
            self.assertFalse(response)
            return

        domain, username = service_username.split('\\')
        if domain != ".":
            self.assertEqual(
                ["Skipping password reset, service running as a domain "
                 "account: %s" % service_username], self.snatcher.output)
            self.assertFalse(response)
            return

        mock_set_password.assert_called_once_with(username,
                                                  mock.sentinel.password)
        mock_set_credentials.assert_called_once_with(
            self._winutils._service_name, service_username,
            mock.sentinel.password)
        self.assertEqual(mock_generate_password.call_count, 1)
        self.assertTrue(response)

    def test_reset_service_password(self):
        self._test_reset_service_password(
            service_exists=True, service_username="EXAMPLE.COM\\username")

    def test_reset_service_password_no_service(self):
        self._test_reset_service_password(service_exists=False,
                                          service_username=None)

    def test_reset_service_password_built_in_account(self):
        self._test_reset_service_password(service_exists=True,
                                          service_username="username")

    def test_reset_service_password_domain_account(self):
        self._test_reset_service_password(service_exists=True,
                                          service_username=".\\username")

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_get_service_status(self, mock_get_service_handle):
        mock_hs = mock.MagicMock()
        fake_service_name = "fake name"
        fake_status = {'CurrentState': 'fake-status'}
        mock_get_service_handle.return_value = mock_hs
        expected_log = ["Getting service status for: %s" % fake_service_name]
        self._win32service_mock.QueryServiceStatusEx.return_value = fake_status
        with self.snatcher:
            response = self._winutils.get_service_status(fake_service_name)

        self._win32service_mock.QueryServiceStatusEx.assert_called_once_with(
            mock_hs.__enter__())
        mock_get_service_handle.assert_called_once_with(
            fake_service_name, self._win32service_mock.SERVICE_QUERY_STATUS)
        self.assertEqual(self.snatcher.output, expected_log)
        self.assertEqual("Unknown", response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_get_service_start_mode(self, mock_get_service_handle):
        mock_hs = mock.MagicMock()
        fake_service_name = "fake name"
        mock_mode = self._win32service_mock.SERVICE_AUTO_START
        fake_status = ['', mock_mode]
        mock_get_service_handle.return_value = mock_hs
        expected_mode = "Automatic"
        expected_log = [
            "Getting service start mode for: %s" % fake_service_name]
        self._win32service_mock.QueryServiceConfig.return_value = fake_status

        with self.snatcher:
            response = self._winutils.get_service_start_mode(fake_service_name)

        self._win32service_mock.QueryServiceConfig.assert_called_once_with(
            mock_hs.__enter__())
        mock_get_service_handle.assert_called_once_with(
            fake_service_name, self._win32service_mock.SERVICE_QUERY_CONFIG)
        self.assertEqual(self.snatcher.output, expected_log)
        self.assertEqual(expected_mode, response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_set_service_start_mode(self, mock_get_service_handle):
        mock_hs = mock.MagicMock()
        fake_service_name = "fake name"
        fake_start_mode = "Automatic"
        mock_get_service_handle.return_value = mock_hs
        with self.snatcher:
            self._winutils.set_service_start_mode(fake_service_name,
                                                  fake_start_mode)
            self.assertEqual(["Setting service start mode for: fake name"],
                             self.snatcher.output)
        self._win32service_mock.ChangeServiceConfig.assert_called_once_with(
            mock_hs.__enter__(),
            self._win32service_mock.SERVICE_NO_CHANGE,
            self._win32service_mock.SERVICE_AUTO_START,
            self._win32service_mock.SERVICE_NO_CHANGE,
            None, None, False, None, None, None, None)
        mock_get_service_handle.assert_called_once_with(
            fake_service_name,
            self._win32service_mock.SERVICE_CHANGE_CONFIG)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_start_service(self, mock_get_service_handle):
        mock_hs = mock.MagicMock()
        fake_service_name = "fake name"
        mock_get_service_handle.return_value = mock_hs
        with self.snatcher:
            self._winutils.start_service(fake_service_name)
            self.assertEqual(["Starting service fake name"],
                             self.snatcher.output)
        self._win32service_mock.StartService.assert_called_once_with(
            mock_hs.__enter__(), fake_service_name)
        mock_get_service_handle.assert_called_once_with(
            fake_service_name, self._win32service_mock.SERVICE_START)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service_handle')
    def test_stop_service(self, mock_get_service_handle):
        mock_hs = mock.MagicMock()
        fake_service_name = "fake name"
        mock_get_service_handle.return_value = mock_hs
        with self.snatcher:
            self._winutils.stop_service(fake_service_name)
            self.assertEqual(["Stopping service fake name"],
                             self.snatcher.output)
        self._win32service_mock.ControlService.assert_called_once_with(
            mock_hs.__enter__(),
            self._win32service_mock.SERVICE_CONTROL_STOP)
        mock_get_service_handle.assert_called_once_with(
            fake_service_name, self._win32service_mock.SERVICE_STOP |
            self._win32service_mock.SERVICE_QUERY_STATUS)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.stop_service')
    @mock.patch('time.sleep')
    def test_terminate(self, mock_sleep, mock_stop_service):
        self._winutils.terminate()
        mock_stop_service.assert_called_with(self._winutils._service_name)
        mock_sleep.assert_called_with(3)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_ipv4_routing_table')
    def _test_get_default_gateway(self, mock_get_ipv4_routing_table,
                                  routing_table):
        mock_get_ipv4_routing_table.return_value = [routing_table]
        response = self._winutils.get_default_gateway()
        mock_get_ipv4_routing_table.assert_called_once_with()
        if routing_table[0] == '0.0.0.0':
            self.assertEqual((routing_table[3], routing_table[2]), response)
        else:
            self.assertEqual((None, None), response)

    def test_get_default_gateway(self):
        routing_table = ['0.0.0.0', '1.1.1.1', self._GATEWAY, '8.8.8.8']
        self._test_get_default_gateway(routing_table=routing_table)

    def test_get_default_gateway_error(self):
        routing_table = ['1.1.1.1', '1.1.1.1', self._GATEWAY, '8.8.8.8']
        self._test_get_default_gateway(routing_table=routing_table)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_ipv4_routing_table')
    def _test_check_static_route_exists(self, mock_get_ipv4_routing_table,
                                        routing_table):
        mock_get_ipv4_routing_table.return_value = [routing_table]

        response = self._winutils.check_static_route_exists(self._DESTINATION)

        mock_get_ipv4_routing_table.assert_called_once_with()
        if routing_table[0] == self._DESTINATION:
            self.assertTrue(response)
        else:
            self.assertFalse(response)

    def test_check_static_route_exists_true(self):
        routing_table = [self._DESTINATION, '1.1.1.1', self._GATEWAY,
                         '8.8.8.8']
        self._test_check_static_route_exists(routing_table=routing_table)

    def test_check_static_route_exists_false(self):
        routing_table = ['0.0.0.0', '1.1.1.1', self._GATEWAY, '8.8.8.8']
        self._test_check_static_route_exists(routing_table=routing_table)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.execute_process')
    def _test_add_static_route(self, mock_execute_process, err):
        next_hop = '10.10.10.10'
        interface_index = 1
        metric = 9
        args = ['ROUTE', 'ADD', self._DESTINATION, 'MASK', self._NETMASK,
                next_hop]
        mock_execute_process.return_value = (None, err, None)

        if err:
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.add_static_route,
                              self._DESTINATION, self._NETMASK, next_hop,
                              interface_index, metric)

        else:
            self._winutils.add_static_route(self._DESTINATION, self._NETMASK,
                                            next_hop, interface_index, metric)
            mock_execute_process.assert_called_with(args)

    def test_add_static_route(self):
        self._test_add_static_route(err=404)

    def test_add_static_route_fail(self):
        self._test_add_static_route(err=None)

    def _test_check_os_version(self, ret_val=None, fail=False):
        params = (3, 1, 2)
        mock_version_info = self._ntdll.RtlVerifyVersionInfo
        mock_version_info.return_value = ret_val
        mask = mock.Mock()
        mock_condition_mask = self._kernel32.VerSetConditionMask
        mock_condition_mask.return_value = mask
        ver_constants = [
            self.windows_utils.VER_MAJORVERSION,
            self.windows_utils.VER_MINORVERSION,
            self.windows_utils.VER_BUILDNUMBER]

        if fail:
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.check_os_version(*params)
            return

        osversion_struct = self.windows_utils.Win32_OSVERSIONINFOEX_W
        osversion_struct.return_value = osversion_struct()
        osversion_struct.side_effect = None
        vi = osversion_struct()
        mask_calls = [
            mock.call(0, ver_constants[0],
                      self.windows_utils.VER_GREATER_EQUAL),
            mock.call(mask, ver_constants[1],
                      self.windows_utils.VER_GREATER_EQUAL),
            mock.call(mask, ver_constants[2],
                      self.windows_utils.VER_GREATER_EQUAL)]

        response = self._winutils.check_os_version(*params)
        self._ctypes_mock.sizeof.assert_called_once_with(osversion_struct)
        mock_condition_mask.assert_has_calls(mask_calls)
        type_mask = ver_constants[0] | ver_constants[1] | ver_constants[2]
        self._ctypes_mock.byref.assert_called_once_with(vi)
        mock_version_info.assert_called_once_with(
            self._ctypes_mock.byref.return_value, type_mask, mask)

        expect = None
        if not ret_val:
            expect = True
        elif ret_val == self._winutils.STATUS_REVISION_MISMATCH:
            expect = False
        self.assertEqual(expect, response)

    def test_check_os_version_pass(self):
        self._test_check_os_version(ret_val=0)

    def test_check_os_version_no_pass(self):
        self._test_check_os_version(
            ret_val=self._winutils.STATUS_REVISION_MISMATCH)

    def test_check_os_version_fail(self):
        self._test_check_os_version(ret_val=mock.Mock(), fail=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_os_version')
    def test_is_client_os(self, mock_get_os_version):
        mock_get_os_version.return_value = {
            "product_type": self._winutils.VER_NT_WORKSTATION}

        self.assertEqual(True, self._winutils.is_client_os())

    def _test_get_volume_label(self, ret_val):
        label = mock.MagicMock()
        max_label_size = 261
        drive = 'Fake_drive'
        self._ctypes_mock.create_unicode_buffer.return_value = label
        self._windll_mock.kernel32.GetVolumeInformationW.return_value = ret_val

        response = self._winutils.get_volume_label(drive)

        if ret_val:
            self.assertTrue(response is not None)
        else:
            self.assertTrue(response is None)

        self._ctypes_mock.create_unicode_buffer.assert_called_with(
            max_label_size)
        self._windll_mock.kernel32.GetVolumeInformationW.assert_called_with(
            drive, label, max_label_size, 0, 0, 0, 0, 0)

    def test_get_volume_label(self):
        self._test_get_volume_label('ret')

    def test_get_volume_label_no_return_value(self):
        self._test_get_volume_label(None)

    def _test_get_volume_path_names_by_mount_point(self, err=False,
                                                   last_err=None,
                                                   volume_name=None):
        mock_mount_point = mock.Mock()
        self._windll_mock.kernel32.GetLastError.return_value = last_err
        if err:
            (self._windll_mock.kernel32.
                GetVolumeNameForVolumeMountPointW.return_value) = None
            if last_err in [self._winutils.ERROR_INVALID_NAME,
                            self._winutils.ERROR_PATH_NOT_FOUND]:
                self.assertRaises(
                    exception.ItemNotFoundException,
                    self._winutils.get_volume_path_names_by_mount_point,
                    mock_mount_point)
            else:
                self.assertRaises(
                    exception.WindowsCloudbaseInitException,
                    self._winutils.get_volume_path_names_by_mount_point,
                    mock_mount_point)
            return
        (self._windll_mock.kernel32.
            GetVolumePathNamesForVolumeNameW.return_value) = volume_name
        if not volume_name:
            if last_err != self._winutils.ERROR_MORE_DATA:
                self.assertRaises(
                    exception.WindowsCloudbaseInitException,
                    self._winutils.get_volume_path_names_by_mount_point,
                    mock_mount_point)

    def test_get_volume_path_names_by_mount_point_not_found(self):
        self._test_get_volume_path_names_by_mount_point(err=True)

    def test_get_volume_path_names_by_mount_point_failed(self):
        self._test_get_volume_path_names_by_mount_point(
            err=True, last_err=self._winutils.ERROR_INVALID_NAME)

    def test_get_volume_path_names_by_mount_point_error(self):
        self._test_get_volume_path_names_by_mount_point(
            volume_name=True, last_err=self._winutils.ERROR_MORE_DATA)

    @mock.patch('re.search')
    @mock.patch('cloudbaseinit.osutils.base.BaseOSUtils.'
                'generate_random_password')
    def test_generate_random_password(self, mock_generate_random_password,
                                      mock_search):
        length = 14
        mock_search.return_value = True
        mock_generate_random_password.return_value = 'Passw0rd'

        response = self._winutils.generate_random_password(length)

        mock_generate_random_password.assert_called_once_with(length)
        self.assertEqual('Passw0rd', response)

    def test_generate_random_password_less_than_3(self):
        with self.assertRaises(exception.CloudbaseInitException) as ex:
            self._winutils.generate_random_password(2)
        self.assertEqual(str(ex.exception),
                         "Password can not have less than 3 characters!")

    def _test_get_logical_drives(self, buf_length, last_error=None):
        mock_buf = mock.MagicMock()
        mock_buf.__getitem__.side_effect = ['1', '\x00']
        mock_get_drives = self._windll_mock.kernel32.GetLogicalDriveStringsW

        self._ctypes_mock.create_unicode_buffer.return_value = mock_buf
        mock_get_drives.return_value = buf_length

        if buf_length is None:
            with self.assert_raises_windows_message(
                    "GetLogicalDriveStringsW failed: %r", last_error):
                self._winutils.get_logical_drives()
        else:
            response = self._winutils.get_logical_drives()

            self._ctypes_mock.create_unicode_buffer.assert_called_with(261)
            mock_get_drives.assert_called_with(260, mock_buf)
            self.assertEqual(['1'], response)

    def test_get_logical_drives_exception(self):
        self._test_get_logical_drives(buf_length=None, last_error=100)

    def test_get_logical_drives(self):
        self._test_get_logical_drives(buf_length=2)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                'get_logical_drives')
    @mock.patch('cloudbaseinit.osutils.windows.kernel32')
    def test_get_cdrom_drives(self, mock_kernel32, mock_get_logical_drives):
        mock_get_logical_drives.return_value = ['drive']
        mock_kernel32.GetDriveTypeW.return_value = self._winutils.DRIVE_CDROM

        response = self._winutils.get_cdrom_drives()

        mock_get_logical_drives.assert_called_with()
        self.assertEqual(['drive'], response)

    @mock.patch('cloudbaseinit.osutils.windows.msvcrt')
    @mock.patch('cloudbaseinit.osutils.windows.kernel32')
    @mock.patch('cloudbaseinit.osutils.windows.setupapi')
    @mock.patch('cloudbaseinit.osutils.windows.Win32_STORAGE_DEVICE_NUMBER')
    def _test_get_physical_disks(self, mock_sdn, mock_setupapi, mock_kernel32,
                                 mock_msvcrt, handle_disks, last_error,
                                 interface_detail, disk_handle, io_control,
                                 last_error_code=None):

        sizeof_calls = [
            mock.call(
                self.windows_utils.Win32_SP_DEVICE_INTERFACE_DATA
            ),
            mock.call(
                self.windows_utils.Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W
            ),
            mock.call(mock_sdn())
        ]
        device_interfaces_calls = [
            mock.call(
                handle_disks, None, self._ctypes_mock.byref.return_value, 0,
                self._ctypes_mock.byref.return_value),
            mock.call(handle_disks, None,
                      self._ctypes_mock.byref.return_value, 1,
                      self._ctypes_mock.byref.return_value)]
        device_path = self._ctypes_mock.cast.return_value.contents.DevicePath
        cast_calls = [mock.call(mock_msvcrt.malloc(),
                                self._ctypes_mock.POINTER.return_value),
                      mock.call(device_path,
                                self._wintypes_mock.LPWSTR)]

        mock_setup_interface = mock_setupapi.SetupDiGetDeviceInterfaceDetailW

        mock_setupapi.SetupDiGetClassDevsW.return_value = handle_disks
        mock_kernel32.GetLastError.return_value = last_error
        mock_setup_interface.return_value = interface_detail
        mock_kernel32.CreateFileW.return_value = disk_handle
        mock_kernel32.DeviceIoControl.return_value = io_control

        mock_setupapi.SetupDiEnumDeviceInterfaces.side_effect = [True, False]

        if handle_disks == self._winutils.INVALID_HANDLE_VALUE or (
            last_error != self._winutils.ERROR_INSUFFICIENT_BUFFER) and not (
                interface_detail) or (
                    disk_handle == self._winutils.INVALID_HANDLE_VALUE) or (
                        not io_control):
            if not io_control:
                with self.assert_raises_windows_message(
                        "DeviceIoControl failed: %r", last_error_code):
                    self._winutils.get_physical_disks()
            elif not interface_detail:
                with self.assert_raises_windows_message(
                        "SetupDiGetDeviceInterfaceDetailW failed: %r",
                        last_error_code):
                    self._winutils.get_physical_disks()
            else:
                self.assertRaises(exception.CloudbaseInitException,
                                  self._winutils.get_physical_disks)

        else:
            response = self._winutils.get_physical_disks()

            self.assertEqual(sizeof_calls,
                             self._ctypes_mock.sizeof.call_args_list)

            self.assertEqual(
                device_interfaces_calls,
                mock_setupapi.SetupDiEnumDeviceInterfaces.call_args_list)

            if not interface_detail:
                mock_kernel32.GetLastError.assert_called_once_with()

            self._ctypes_mock.POINTER.assert_called_with(
                self.windows_utils.Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W)
            mock_msvcrt.malloc.assert_called_with(
                self._ctypes_mock.c_size_t.return_value
            )

            self.assertEqual(cast_calls, self._ctypes_mock.cast.call_args_list)

            mock_setup_interface.assert_called_with(
                handle_disks, self._ctypes_mock.byref.return_value,
                self._ctypes_mock.cast.return_value,
                self._wintypes_mock.DWORD.return_value,
                None, None)

            mock_kernel32.CreateFileW.assert_called_with(
                self._ctypes_mock.cast.return_value.value, 0,
                self._winutils.FILE_SHARE_READ, None,
                self._winutils.OPEN_EXISTING, 0, 0)
            mock_sdn.assert_called_with()

            mock_kernel32.DeviceIoControl.assert_called_with(
                disk_handle, self._winutils.IOCTL_STORAGE_GET_DEVICE_NUMBER,
                None, 0, self._ctypes_mock.byref.return_value,
                self._ctypes_mock.sizeof.return_value,
                self._ctypes_mock.byref.return_value, None)

            self.assertEqual(["\\\\.\PHYSICALDRIVE1"], response)

            mock_setupapi.SetupDiDestroyDeviceInfoList.assert_called_once_with(
                handle_disks)

        mock_setupapi.SetupDiGetClassDevsW.assert_called_once_with(
            self._ctypes_mock.byref.return_value, None, None,
            self._winutils.DIGCF_PRESENT |
            self._winutils.DIGCF_DEVICEINTERFACE)

    def test_get_physical_disks(self):
        mock_handle_disks = mock.MagicMock()
        mock_disk_handle = mock.MagicMock()
        self._test_get_physical_disks(
            handle_disks=mock_handle_disks,
            last_error=self._winutils.ERROR_INSUFFICIENT_BUFFER,
            interface_detail='fake interface detail',
            disk_handle=mock_disk_handle, io_control=True)

    def test_get_physical_disks_other_error_and_no_interface_detail(self):
        mock_handle_disks = mock.MagicMock()
        mock_disk_handle = mock.MagicMock()
        self._test_get_physical_disks(
            handle_disks=mock_handle_disks,
            last_error='other', interface_detail=None,
            last_error_code=100,
            disk_handle=mock_disk_handle, io_control=True)

    def test_get_physical_disks_invalid_disk_handle(self):
        mock_handle_disks = mock.MagicMock()
        self._test_get_physical_disks(
            handle_disks=mock_handle_disks,
            last_error=self._winutils.ERROR_INSUFFICIENT_BUFFER,
            interface_detail='fake interface detail',
            disk_handle=self._winutils.INVALID_HANDLE_VALUE, io_control=True)

    def test_get_physical_disks_io_control(self):
        mock_handle_disks = mock.MagicMock()
        mock_disk_handle = mock.MagicMock()
        self._test_get_physical_disks(
            handle_disks=mock_handle_disks,
            last_error=self._winutils.ERROR_INSUFFICIENT_BUFFER,
            interface_detail='fake interface detail',
            last_error_code=100,
            disk_handle=mock_disk_handle, io_control=False)

    def test_get_physical_disks_handle_disks_invalid(self):
        mock_disk_handle = mock.MagicMock()
        self._test_get_physical_disks(
            handle_disks=self._winutils.INVALID_HANDLE_VALUE,
            last_error=self._winutils.ERROR_INSUFFICIENT_BUFFER,
            interface_detail='fake interface detail',
            disk_handle=mock_disk_handle, io_control=True)

    def _test_get_volumes(self, find_first=True, find_next=True):
        count = 3
        expected_volumes = ["ID_{}".format(idx) for idx in range(count)]

        volume_values = mock.PropertyMock(side_effect=expected_volumes)
        mock_volume = mock.Mock()
        type(mock_volume).value = volume_values
        self._ctypes_mock.create_unicode_buffer.return_value = mock_volume

        if not find_first:
            self._kernel32.FindFirstVolumeW.return_value = self._winutils\
                .INVALID_HANDLE_VALUE
        side_effects = [1] * (count - 1)
        side_effects.append(0)
        self._kernel32.FindNextVolumeW.side_effect = side_effects
        if find_next:
            self._ctypes_mock.GetLastError.return_value = self._winutils\
                .ERROR_NO_MORE_FILES
        if not (find_first and find_next):
            with self.assertRaises(exception.WindowsCloudbaseInitException):
                self._winutils.get_volumes()
            return

        volumes = self._winutils.get_volumes()
        self._kernel32.FindFirstVolumeW.assert_called_once_with(
            mock_volume, self._winutils.MAX_PATH)
        find_next_calls = [
            mock.call(self._kernel32.FindFirstVolumeW.return_value,
                      mock_volume, self._winutils.MAX_PATH)] * count
        self._kernel32.FindNextVolumeW.assert_has_calls(find_next_calls)
        self._kernel32.FindVolumeClose.assert_called_once_with(
            self._kernel32.FindFirstVolumeW.return_value)
        self.assertEqual(expected_volumes, volumes)

    def test_get_volumes(self):
        self._test_get_volumes()

    def test_get_volumes_first_fail(self):
        self._test_get_volumes(find_first=False)

    def test_get_volumes_next_fail(self):
        self._test_get_volumes(find_next=False)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils._get_fw_protocol')
    def test_firewall_create_rule(self, mock_get_fw_protocol):
        expected = [mock.call("HNetCfg.FWOpenPort"),
                    mock.call("HNetCfg.FwMgr")]

        self._winutils.firewall_create_rule(
            name='fake name', port=9999, protocol=self._winutils.PROTOCOL_TCP)

        self.assertEqual(expected, self._client_mock.Dispatch.call_args_list)
        mock_get_fw_protocol.assert_called_once_with(
            self._winutils.PROTOCOL_TCP)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils._get_fw_protocol')
    def test_firewall_remove_rule(self, mock_get_fw_protocol):
        self._winutils.firewall_remove_rule(
            name='fake name', port=9999, protocol=self._winutils.PROTOCOL_TCP)

        self._client_mock.Dispatch.assert_called_once_with("HNetCfg.FwMgr")
        mock_get_fw_protocol.assert_called_once_with(
            self._winutils.PROTOCOL_TCP)

    @mock.patch('os.path.expandvars')
    def test_get_system32_dir(self, mock_expandvars):
        path = "system32"
        mock_expandvars.return_value = path
        response = self._winutils.get_system32_dir()

        mock_expandvars.assert_called_once_with('%windir%\\{}'.format(path))
        self.assertEqual(path, response)

    @mock.patch('os.path.expandvars')
    def test_get_syswow64_dir(self, mock_expandvars):
        path = "syswow64"
        mock_expandvars.return_value = path
        response = self._winutils.get_syswow64_dir()

        mock_expandvars.assert_called_once_with('%windir%\\{}'.format(path))
        self.assertEqual(path, response)

    @mock.patch('os.path.expandvars')
    def test_get_sysnative_dir(self, mock_expandvars):
        path = "sysnative"
        mock_expandvars.return_value = path
        response = self._winutils.get_sysnative_dir()

        mock_expandvars.assert_called_once_with('%windir%\\{}'.format(path))
        self.assertEqual(path, response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.is_wow64')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_sysnative_dir')
    @mock.patch('os.path.isdir')
    def _test_check_sysnative_dir_exists(self, mock_isdir,
                                         mock_get_sysnative_dir,
                                         mock_is_wow64,
                                         exists=True, wow64=False):
        mock_get_sysnative_dir.return_value = 'fake_sysnative'
        mock_isdir.return_value = exists
        mock_is_wow64.return_value = wow64

        with self.snatcher:
            response = self._winutils.check_sysnative_dir_exists()

        expected_log = []
        if not exists and wow64:
            expected_log = ['Unable to validate sysnative folder presence. '
                            'If Target OS is Server 2003 x64, please ensure '
                            'you have KB942589 installed']
        self.assertEqual(expected_log, self.snatcher.output)
        self.assertEqual(exists, response)

    def test_check_sysnative_dir_exists(self):
        self._test_check_sysnative_dir_exists()

    def test_check_sysnative_dir_does_not_exist(self):
        self._test_check_sysnative_dir_exists(exists=False, wow64=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_sysnative_dir_exists')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_sysnative_dir')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._is_64bit_arch')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_syswow64_dir')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_system32_dir')
    def _test_get_system_dir(self, mock_get_system32_dir,
                             mock_get_syswow64_dir,
                             mock_is_64bit_arch,
                             mock_get_sysnative_dir,
                             mock_check_sysnative_dir_exists,
                             sysnative, arches):
        # settings
        mock_get_system32_dir.return_value = "system32"
        mock_get_syswow64_dir.return_value = "syswow64"
        mock_get_sysnative_dir.return_value = "sysnative"
        mock_is_64bit_arch.return_value = arches.startswith("64")
        mock_check_sysnative_dir_exists.return_value = (arches == "32on64")
        expect_dict = {
            "32on32": {
                False: (
                    "system32",
                    [mock_is_64bit_arch, mock_get_system32_dir]
                ),
                True: (
                    "system32",
                    [mock_check_sysnative_dir_exists,
                     mock_get_system32_dir]
                )
            },
            "32on64": {
                False: (
                    "system32",
                    [mock_is_64bit_arch, mock_get_system32_dir]
                ),
                True: (
                    "sysnative",
                    [mock_check_sysnative_dir_exists,
                     mock_get_sysnative_dir]
                )
            },
            "64on64": {
                False: (
                    "syswow64",
                    [mock_is_64bit_arch, mock_get_syswow64_dir]
                ),
                True: (
                    "system32",
                    [mock_check_sysnative_dir_exists,
                     mock_get_system32_dir]
                )
            }
        }
        # actions
        response = self._winutils._get_system_dir(sysnative=sysnative)
        expect, calls = expect_dict[arches][sysnative]
        self.assertEqual(expect, response)
        for call in calls:
            call.assert_called_once_with()

    def test_get_system_dir_32on32(self):
        arches = "32on32"
        self._test_get_system_dir(sysnative=False, arches=arches)
        self._test_get_system_dir(sysnative=True, arches=arches)

    def test_get_system_dir_32on64(self):
        arches = "32on64"
        self._test_get_system_dir(sysnative=False, arches=arches)
        self._test_get_system_dir(sysnative=True, arches=arches)

    def test_get_system_dir_64on64(self):
        arches = "64on64"
        self._test_get_system_dir(sysnative=False, arches=arches)
        self._test_get_system_dir(sysnative=True, arches=arches)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._check_server_level')
    def test_is_nano_server(self, mock_check_server_level):
        expect = mock.Mock()
        mock_check_server_level.return_value = expect
        response = self._winutils.is_nano_server()
        mock_check_server_level.assert_called_once_with("NanoServer")
        self.assertEqual(expect, response)

    def _test_check_server_level(self, fail=False, success=True):
        server_level = mock.Mock()
        open_key = self._winreg_mock.OpenKey

        if not success:
            eclass = Exception
            error = eclass()
            self.windows_utils.WindowsError = eclass
            open_key.side_effect = [error]
            if fail:
                with self.assertRaises(eclass):
                    self._winutils._check_server_level(server_level)
                return
            error.winerror = 2
            response = self._winutils._check_server_level(server_level)
            self.assertEqual(False, response)
            return

        self.used_hive, self.used_path = None, None
        mock_key = mock.Mock()

        @contextlib.contextmanager
        def open_key_context(hive, path):
            self.used_hive, self.used_path = hive, path
            yield mock_key

        self._winreg_mock.OpenKey = open_key_context
        self._winreg_mock.QueryValueEx.return_value = [1]
        response = self._winutils._check_server_level(server_level)
        self.assertEqual(self._winreg_mock.HKEY_LOCAL_MACHINE,
                         self.used_hive)
        self.assertEqual("Software\\Microsoft\\Windows NT\\"
                         "CurrentVersion\\Server\\ServerLevels",
                         self.used_path)
        self._winreg_mock.QueryValueEx.assert_called_once_with(
            mock_key, server_level)
        self.assertEqual(True, response)

    def test_check_server_level_fail(self):
        self._test_check_server_level(fail=True, success=False)

    def test_check_server_level_no_success(self):
        self._test_check_server_level(fail=False, success=False)

    def test_check_server_level_success(self):
        self._test_check_server_level()

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.is_nano_server')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_sysnative_dir_exists')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_sysnative_dir')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_system32_dir')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.execute_process')
    def _test_execute_powershell_script(self, mock_execute_process,
                                        mock_get_system32_dir,
                                        mock_get_sysnative_dir,
                                        mock_check_sysnative_dir_exists,
                                        mock_is_nano_server,
                                        ret_val=None, nano=False):
        mock_check_sysnative_dir_exists.return_value = ret_val
        mock_is_nano_server.return_value = nano
        mock_get_sysnative_dir.return_value = 'fake'
        mock_get_system32_dir.return_value = 'fake'
        fake_path = os.path.join('fake', 'WindowsPowerShell\\v1.0\\'
                                         'powershell.exe')
        args = [fake_path]
        if not nano:
            args.extend(['-ExecutionPolicy', 'RemoteSigned',
                         '-NonInteractive', '-File'])
        args.append('fake_script_path')

        response = self._winutils.execute_powershell_script(
            script_path='fake_script_path')

        if ret_val:
            mock_get_sysnative_dir.assert_called_once_with()
        else:
            mock_get_system32_dir.assert_called_once_with()

        mock_execute_process.assert_called_with(args, shell=False)
        self.assertEqual(mock_execute_process.return_value, response)

    def test_execute_powershell_script_sysnative(self):
        self._test_execute_powershell_script(ret_val=True)

    def test_execute_powershell_script_system32(self):
        self._test_execute_powershell_script(ret_val=False)

    def test_execute_powershell_script_sysnative_nano(self):
        self._test_execute_powershell_script(ret_val=True, nano=True)

    @mock.patch('cloudbaseinit.utils.windows.network.get_adapter_addresses')
    def test_get_dhcp_hosts_in_use(self, mock_get_adapter_addresses):
        net_addr = {}
        net_addr["friendly_name"] = mock.sentinel.friendly_name
        net_addr["mac_address"] = mock.sentinel.mac_address
        net_addr["dhcp_server"] = mock.sentinel.dhcp_server
        net_addr["dhcp_enabled"] = True
        mock_get_adapter_addresses.return_value = [net_addr]

        response = self._winutils.get_dhcp_hosts_in_use()

        mock_get_adapter_addresses.assert_called_once_with()
        self.assertEqual([(mock.sentinel.friendly_name,
                           mock.sentinel.mac_address,
                           mock.sentinel.dhcp_server)], response)

    def test_fix_network_adapter_dhcp(self):
        self._test_fix_network_adapter_dhcp(True)

    def test_fix_network_adapter_dhcp_no_network_adapter(self):
        self._test_fix_network_adapter_dhcp(False)

    def _test_fix_network_adapter_dhcp(self, no_net_interface_found):
        mock_interface_name = "eth12"
        mock_enable_dhcp = True
        mock_address_family = self.windows_utils.AF_INET

        conn = self._wmi_mock.WMI.return_value
        existing_net_interface = mock.Mock()
        existing_net_interface.Dhcp = 0

        if not no_net_interface_found:
            conn.MSFT_NetIPInterface.return_value = [existing_net_interface]

        if no_net_interface_found:
            with self.assertRaises(exception.ItemNotFoundException):
                self._winutils._fix_network_adapter_dhcp(
                    mock_interface_name, mock_enable_dhcp,
                    mock_address_family)
        else:
            self._winutils._fix_network_adapter_dhcp(
                mock_interface_name, mock_enable_dhcp,
                mock_address_family)

            conn.MSFT_NetIPInterface.assert_called_once_with(
                InterfaceAlias=mock_interface_name,
                AddressFamily=mock_address_family)
            self.assertEqual(existing_net_interface.Dhcp, 1)
            existing_net_interface.put.assert_called_once()

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_sysnative_dir_exists')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_sysnative_dir')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_system32_dir')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.execute_process')
    def _test_set_ntp_client_config(self, mock_execute_process,
                                    mock_get_system32_dir,
                                    mock_get_sysnative_dir,
                                    mock_check_sysnative_dir_exists,
                                    sysnative, ret_val):
        fake_base_dir = 'fake_dir'
        ntp_hosts = ["first", "second"]

        mock_check_sysnative_dir_exists.return_value = sysnative
        mock_execute_process.return_value = (None, None, ret_val)
        w32tm_path = os.path.join(fake_base_dir, "w32tm.exe")
        mock_get_sysnative_dir.return_value = fake_base_dir
        mock_get_system32_dir.return_value = fake_base_dir

        args = [w32tm_path, '/config',
                '/manualpeerlist:%s' % ",".join(ntp_hosts),
                '/syncfromflags:manual', '/update']

        if ret_val:
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.set_ntp_client_config,
                              'fake ntp host')

        else:
            self._winutils.set_ntp_client_config(ntp_hosts=ntp_hosts)

            if sysnative:
                mock_get_sysnative_dir.assert_called_once_with()
            else:
                mock_get_system32_dir.assert_called_once_with()

            mock_execute_process.assert_called_once_with(args, shell=False)

    def test_set_ntp_client_config_sysnative_true(self):
        self._test_set_ntp_client_config(sysnative=True, ret_val=None)

    def test_set_ntp_client_config_sysnative_false(self):
        self._test_set_ntp_client_config(sysnative=False, ret_val=None)

    def test_set_ntp_client_config_sysnative_exception(self):
        self._test_set_ntp_client_config(sysnative=False,
                                         ret_val='fake return value')

    @mock.patch("cloudbaseinit.utils.windows.network."
                "get_adapter_addresses")
    def _test_get_network_adapter_name_by_mac_address(
            self, mock_get_adapter_addresses,
            no_adapters_found=False,
            multiple_adapters_found=False):

        mock.sentinel.mac_address = "aa:bb:cc:dd:ee:ff"

        if no_adapters_found:
            mock_get_adapter_addresses.return_value = []
        elif multiple_adapters_found:
            mock_get_adapter_addresses.return_value = [{
                "mac_address": mock.sentinel.mac_address,
                "friendly_name": mock.sentinel.friendly_name,
            }, {
                "mac_address": mock.sentinel.mac_address,
                "friendly_name": mock.sentinel.friendly_name2,
            }]
        else:
            mock_get_adapter_addresses.return_value = [{
                "mac_address": mock.sentinel.mac_address.upper(),
                "friendly_name": mock.sentinel.friendly_name,
            }]

        if no_adapters_found:
            with self.assertRaises(exception.ItemNotFoundException):
                self._winutils.get_network_adapter_name_by_mac_address(
                    mock.sentinel.mac_address)
        elif multiple_adapters_found:
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.get_network_adapter_name_by_mac_address(
                    mock.sentinel.mac_address)
        else:
            self.assertEqual(
                mock.sentinel.friendly_name,
                self._winutils.get_network_adapter_name_by_mac_address(
                    mock.sentinel.mac_address))

        mock_get_adapter_addresses.assert_called_once_with()

    def test_get_network_adapter_name_by_mac_address(self):
        self._test_get_network_adapter_name_by_mac_address()

    def test_get_network_adapter_name_by_mac_address_no_adapters(self):
        self._test_get_network_adapter_name_by_mac_address(
            no_adapters_found=True)

    def test_get_network_adapter_name_by_mac_address_multiple_adapters(self):
        self._test_get_network_adapter_name_by_mac_address(
            multiple_adapters_found=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.execute_process')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_system_dir')
    @mock.patch("cloudbaseinit.utils.windows.network."
                "get_adapter_addresses")
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_os_version')
    @mock.patch('time.sleep')
    def _test_set_network_adapter_mtu(self, mock_sleep,
                                      mock_check_os_version,
                                      mock_get_adapter_addresses,
                                      mock_get_system_dir,
                                      mock_execute_process,
                                      fail=False, os_version_ret=True,
                                      name_match=True,
                                      execute_process_val=0):
        name = "fake name"
        index = 1
        mtu = "fake mtu"
        base_dir = "fake path"
        mock_check_os_version.return_value = os_version_ret
        mock_get_adapter_addresses.return_value = [mock.MagicMock()
                                                   for _ in range(3)]
        if name_match:
            mock_get_adapter_addresses.return_value = [
                {"friendly_name": name, "interface_index": index}]
        else:
            mock_get_adapter_addresses.return_value = []

        mock_get_system_dir.return_value = base_dir
        mock_execute_process.return_value = [None, None, execute_process_val]

        if fail:
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.set_network_adapter_mtu(name, mtu)
            return

        with self.snatcher:
            self._winutils.set_network_adapter_mtu(name, mtu)
        expected_log = ['Setting MTU for interface "%(name)s" with '
                        'value "%(mtu)s"' %
                        {'name': name, 'mtu': mtu}]
        args = [os.path.join(base_dir, "netsh.exe"),
                "interface", "ipv4", "set", "subinterface",
                str(index), "mtu=%s" % mtu, "store=persistent"]
        self.assertEqual(expected_log, self.snatcher.output)
        mock_check_os_version.assert_called_once_with(6, 0)
        mock_get_adapter_addresses.assert_called_once_with()
        mock_get_system_dir.assert_called_once_with()
        mock_execute_process.assert_called_once_with(args, shell=False)

    def test_set_network_adapter_mtu_not_supported(self):
        self._test_set_network_adapter_mtu(fail=True, os_version_ret=False)

    def test_set_network_adapter_mtu_no_name_match(self):
        self._test_set_network_adapter_mtu(fail=True,
                                           name_match=False)

    def test_set_network_adapter_mtu_execute_fail(self):
        self._test_set_network_adapter_mtu(fail=True,
                                           execute_process_val=1)

    def test_set_network_adapter_mtu(self):
        self._test_set_network_adapter_mtu()

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                '_get_system_dir')
    @mock.patch('cloudbaseinit.osutils.base.BaseOSUtils.'
                'execute_process')
    def test_execute_system32_process(self, mock_execute_process,
                                      mock_get_system_dir):
        mock_get_system_dir.return_value = 'base_dir'
        mock_execute_process.return_value = mock.sentinel.execute_process
        args = ['command', 'argument']

        result = self._winutils.execute_system32_process(args)
        mock_execute_process.assert_called_once_with(
            [os.path.join('base_dir', args[0])] + args[1:],
            decode_output=False,
            shell=True)
        self.assertEqual(mock.sentinel.execute_process, result)

    def test_get_password_maximum_length(self):
        self.assertEqual(20, self._winutils.get_maximum_password_length())

    @mock.patch('cloudbaseinit.osutils.windows.windows_tz')
    def test_set_timezone_fails(self, mock_windows_tz):
        mock_windows_tz.tz_win.get.return_value = None

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self._winutils.set_timezone(mock.sentinel.timezone)
        expected = (
            "The given timezone name is unrecognised: %r"
            % mock.sentinel.timezone
        )
        self.assertEqual(expected, str(cm.exception))
        mock_windows_tz.tz_win.get.assert_called_once_with(
            mock.sentinel.timezone)

    @mock.patch('cloudbaseinit.osutils.windows.timezone')
    @mock.patch('cloudbaseinit.osutils.windows.windows_tz')
    def test_set_timezone(self, mock_windows_tz, mock_timezone):
        mock_windows_tz.tz_win.get.return_value = (
            mock.sentinel.windows_timezone)

        self._winutils.set_timezone(mock.sentinel.timezone)

        mock_windows_tz.tz_win.get.assert_called_once_with(
            mock.sentinel.timezone)
        mock_timezone.Timezone.assert_called_once_with(
            mock.sentinel.windows_timezone)
        mock_timezone.Timezone.return_value.set.assert_called_once_with(
            self._winutils)

    def _test__heap_alloc(self, fail):
        mock_heap = mock.Mock()
        mock_size = mock.Mock()

        if fail:
            self._kernel32.HeapAlloc.return_value = None

            with self.assertRaises(exception.CloudbaseInitException) as cm:
                self._winutils._heap_alloc(mock_heap, mock_size)

            self.assertEqual('Unable to allocate memory for the IP '
                             'forward table',
                             str(cm.exception))
        else:
            result = self._winutils._heap_alloc(mock_heap, mock_size)
            self.assertEqual(self._kernel32.HeapAlloc.return_value, result)

        self._kernel32.HeapAlloc.assert_called_once_with(
            mock_heap, 0, self._ctypes_mock.c_size_t(mock_size.value))

    def test__heap_alloc_error(self):
        self._test__heap_alloc(fail=True)

    def test__heap_alloc_no_error(self):
        self._test__heap_alloc(fail=False)

    def test__get_forward_table_no_memory(self):
        self._winutils._heap_alloc = mock.Mock()
        error_msg = 'Unable to allocate memory for the IP forward table'
        exc = exception.CloudbaseInitException(error_msg)
        self._winutils._heap_alloc.side_effect = exc

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            with self._winutils._get_forward_table():
                pass

        self.assertEqual(error_msg, str(cm.exception))
        self._winutils._heap_alloc.assert_called_once_with(
            self._kernel32.GetProcessHeap.return_value,
            self._ctypes_mock.wintypes.ULONG.return_value)

    def test__get_forward_table_insufficient_buffer_no_memory(self):
        self._kernel32.HeapAlloc.side_effect = (mock.sentinel.table_mem, None)
        self._iphlpapi.GetIpForwardTable.return_value = (
            self._winutils.ERROR_INSUFFICIENT_BUFFER)

        with self.assertRaises(exception.CloudbaseInitException):
            with self._winutils._get_forward_table():
                pass

        table = self._ctypes_mock.cast.return_value
        self._iphlpapi.GetIpForwardTable.assert_called_once_with(
            table,
            self._ctypes_mock.byref.return_value, 0)
        heap_calls = [
            mock.call(self._kernel32.GetProcessHeap.return_value, 0, table),
            mock.call(self._kernel32.GetProcessHeap.return_value, 0, table)
        ]
        self.assertEqual(heap_calls, self._kernel32.HeapFree.mock_calls)

    def _test__get_forward_table(self, reallocation=False,
                                 insufficient_buffer=False,
                                 fail=False):
        if fail:
            with self.assertRaises(exception.CloudbaseInitException) as cm:
                with self._winutils._get_forward_table():
                    pass

            msg = ('Unable to get IP forward table. Error: %s'
                   % mock.sentinel.error)
            self.assertEqual(msg, str(cm.exception))
        else:
            with self._winutils._get_forward_table() as table:
                pass
            pointer = self._ctypes_mock.POINTER(
                self._iphlpapi.Win32_MIB_IPFORWARDTABLE)
            expected_forward_table = self._ctypes_mock.cast(
                self._kernel32.HeapAlloc.return_value, pointer)
            self.assertEqual(expected_forward_table, table)

        heap_calls = [
            mock.call(self._kernel32.GetProcessHeap.return_value, 0,
                      self._ctypes_mock.cast.return_value)
        ]
        forward_calls = [
            mock.call(self._ctypes_mock.cast.return_value,
                      self._ctypes_mock.byref.return_value, 0),
        ]
        if insufficient_buffer:
            # We expect two calls for GetIpForwardTable
            forward_calls.append(forward_calls[0])
        if reallocation:
            heap_calls.append(heap_calls[0])
        self.assertEqual(heap_calls, self._kernel32.HeapFree.mock_calls)
        self.assertEqual(forward_calls,
                         self._iphlpapi.GetIpForwardTable.mock_calls)

    def test__get_forward_table_sufficient_buffer(self):
        self._iphlpapi.GetIpForwardTable.return_value = None
        self._test__get_forward_table()

    def test__get_forward_table_insufficient_buffer_reallocate(self):
        self._kernel32.HeapAlloc.side_effect = (
            mock.sentinel.table_mem, mock.sentinel.table_mem)
        self._iphlpapi.GetIpForwardTable.side_effect = (
            self._winutils.ERROR_INSUFFICIENT_BUFFER, None)

        self._test__get_forward_table(reallocation=True,
                                      insufficient_buffer=True)

    def test__get_forward_table_insufficient_buffer_other_error(self):
        self._kernel32.HeapAlloc.side_effect = (
            mock.sentinel.table_mem, mock.sentinel.table_mem)
        self._iphlpapi.GetIpForwardTable.side_effect = (
            self._winutils.ERROR_INSUFFICIENT_BUFFER, mock.sentinel.error)

        self._test__get_forward_table(reallocation=True,
                                      insufficient_buffer=True,
                                      fail=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                '_get_forward_table')
    def test_routes(self, mock_forward_table):
        def _same(arg):
            return arg._mock_name.encode()

        route = mock.MagicMock()
        mock_cast_result = mock.Mock()
        mock_cast_result.contents = [route]
        self._ctypes_mock.cast.return_value = mock_cast_result
        self.windows_utils.Ws2_32.inet_ntoa.side_effect = _same
        route.dwForwardIfIndex = 'dwForwardIfIndex'
        route.dwForwardProto = 'dwForwardProto'
        route.dwForwardMetric1 = 'dwForwardMetric1'
        routes = self._winutils._get_ipv4_routing_table()

        mock_forward_table.assert_called_once_with()
        enter = mock_forward_table.return_value.__enter__
        enter.assert_called_once_with()
        exit_ = mock_forward_table.return_value.__exit__
        exit_.assert_called_once_with(None, None, None)
        self.assertEqual(1, len(routes))
        given_route = routes[0]
        self.assertEqual('dwForwardDest', given_route[0])
        self.assertEqual('dwForwardMask', given_route[1])
        self.assertEqual('dwForwardNextHop', given_route[2])
        self.assertEqual('dwForwardIfIndex', given_route[3])
        self.assertEqual('dwForwardMetric1', given_route[4])

    def test_get_current_user(self):
        response = mock.Mock()
        response.value.split.return_value = mock.sentinel.user
        secur32 = self._ctypes_mock.windll.secur32
        self._ctypes_mock.create_unicode_buffer.return_value = response
        secur32.GetUserNameExW.side_effect = [True, False]

        self.assertIs(self._winutils.get_current_user(), mock.sentinel.user)
        with self.assert_raises_windows_message("GetUserNameExW failed: %r",
                                                100):
            self._winutils.get_current_user()

    @mock.patch('cloudbaseinit.osutils.windows.Win32_STARTUPINFO_W')
    @mock.patch('cloudbaseinit.osutils.windows.Win32_PROCESS_INFORMATION')
    @mock.patch('subprocess.list2cmdline')
    def _test_execute_process_as_user(self, mock_list2cmdline, mock_proc_info,
                                      mock_startup_info,
                                      token, args, wait, new_console):
        advapi32 = self._windll_mock.advapi32
        advapi32.CreateProcessAsUserW.return_value = True
        kernel32 = self._ctypes_mock.windll.kernel32
        kernel32.GetExitCodeProcess.return_value = True

        proc_info = mock.Mock()
        proc_info.hProcess = wait
        proc_info.hThread = wait
        mock_proc_info.return_value = proc_info

        command_line = mock.sentinel.command_line
        self._ctypes_mock.create_unicode_buffer.return_value = command_line

        self._winutils.execute_process_as_user(token, args, wait, new_console)

        self.assertEqual(advapi32.CreateProcessAsUserW.call_count, 1)
        if wait:
            kernel32.WaitForSingleObject.assert_called_once_with(
                proc_info.hProcess, self._winutils.INFINITE
            )
            self.assertEqual(kernel32.GetExitCodeProcess.call_count, 1)

        if wait:
            self.assertEqual(kernel32.CloseHandle.call_count, 2)

        mock_list2cmdline.assert_called_once_with(args)

    def test_execute_process_as_user(self):
        self._test_execute_process_as_user(token=mock.sentinel.token,
                                           args=mock.sentinel.args,
                                           wait=False, new_console=False)

    def test_execute_process_as_user_with_wait(self):
        self._test_execute_process_as_user(token=mock.sentinel.token,
                                           args=mock.sentinel.args,
                                           wait=False, new_console=False)

    @mock.patch('cloudbaseinit.osutils.windows.Win32_STARTUPINFO_W')
    @mock.patch('cloudbaseinit.osutils.windows.Win32_PROCESS_INFORMATION')
    @mock.patch('subprocess.list2cmdline')
    def test_execute_process_as_user_fail(self, mock_list2cmdline,
                                          mock_proc_info, mock_startup_info):
        advapi32 = self._windll_mock.advapi32
        advapi32.CreateProcessAsUserW.side_effect = [False, True]
        kernel32 = self._ctypes_mock.windll.kernel32
        kernel32.GetExitCodeProcess.return_value = False
        mock_proc_info.hProcess = True

        token = mock.sentinel.token
        args = mock.sentinel.args
        new_console = mock.sentinel.new_console

        with self.assert_raises_windows_message("CreateProcessAsUserW "
                                                "failed: %r", 100):
            self._winutils.execute_process_as_user(token, args, False,
                                                   new_console)
        with self.assert_raises_windows_message("GetExitCodeProcess "
                                                "failed: %r", 100):
            self._winutils.execute_process_as_user(token, args, True,
                                                   new_console)

    def _test_is_realtime_clock_uct(self, utc=1, exception=False,
                                    exception_raised=False):

        if exception:
            eclass = Exception
            ex = eclass()
            self.windows_utils.WindowsError = eclass
            if not exception_raised:
                ex.winerror = 2
            else:
                ex.winerror = mock.sentinel.winerror
            self._winreg_mock.QueryValueEx.side_effect = ex

        self._winreg_mock.QueryValueEx.return_value = [utc]

        if exception_raised:
            with self.assertRaises(eclass):
                self._winutils.is_real_time_clock_utc()
            response = None
        else:
            response = self._winutils.is_real_time_clock_utc()

        if exception_raised:
            expected_result = None
        elif exception:
            expected_result = False
        else:
            if utc == 0:
                expected_result = utc
            else:
                expected_result = utc != 0

        self.assertEqual(response, expected_result)

        self._winreg_mock.OpenKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            'SYSTEM\\CurrentControlSet\\Control\\'
            'TimeZoneInformation')
        self._winreg_mock.QueryValueEx.assert_called_with(
            self._winreg_mock.OpenKey.return_value.__enter__.return_value,
            'RealTimeIsUniversal')

    def test_is_realtime_clock_utc(self):
        self._test_is_realtime_clock_uct()

    def test_is_not_realtime_clock_utc(self):
        self._test_is_realtime_clock_uct(utc=0)

    def test_is_realtime_clock_utc_registry_value_missing(self):
        self._test_is_realtime_clock_uct(exception=True)

    def test_is_realtime_clock_utc_exception_raised(self):
        self._test_is_realtime_clock_uct(exception=True,
                                         exception_raised=True)

    def _test_set_real_time_clock_utc(self, utc):
        self._winutils.set_real_time_clock_utc(utc)

        self._winreg_mock.OpenKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            'SYSTEM\\CurrentControlSet\\Control\\'
            'TimeZoneInformation',
            0, self._winreg_mock.KEY_ALL_ACCESS)

        key = self._winreg_mock.OpenKey.return_value.__enter__.return_value
        self._winreg_mock.SetValueEx.assert_called_with(
            key, 'RealTimeIsUniversal', 0, self._winreg_mock.REG_DWORD,
            1 if utc else 0)

    def test_set_real_time_clock_utc_set_zero(self):
        self._test_set_real_time_clock_utc(utc=0)

    def test_set_real_time_clock_utc(self):
        self._test_set_real_time_clock_utc(utc=1)

    def test_get_page_files(self):
        mock_value = [u'?:\\pagefile.sys']
        expected_page_files = [(mock_value[0], 0, 0)]
        self._winreg_mock.QueryValueEx.return_value = [mock_value]
        res = self._winutils.get_page_files()
        key = self._winreg_mock.OpenKey.return_value.__enter__.return_value
        self._winreg_mock.OpenKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            'SYSTEM\\CurrentControlSet\\Control\\'
            'Session Manager\\Memory Management')
        self._winreg_mock.QueryValueEx.assert_called_with(key, 'PagingFiles')
        self.assertEqual(res, expected_page_files)

    def test_set_page_files(self):
        mock_path = mock.Mock()
        page_files = [(mock_path, 0, 0)]
        self._winutils.set_page_files(page_files)
        expected_values = ["%s %d %d" % (mock_path, 0, 0)]
        key = self._winreg_mock.OpenKey.return_value.__enter__.return_value
        self._winreg_mock.OpenKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            'SYSTEM\\CurrentControlSet\\Control\\'
            'Session Manager\\Memory Management',
            0, self._winreg_mock.KEY_ALL_ACCESS)
        self._winreg_mock.SetValueEx.assert_called_with(
            key, 'PagingFiles', 0, self._winreg_mock.REG_MULTI_SZ,
            expected_values)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.execute_system32_process')
    def _test_trim(self, mock_execute_process, err):
        if err:
            mock_execute_process.return_value = ("fake out", "", 1)
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.enable_trim, True)
        else:
            args = ["fsutil.exe", "behavior",
                    "set", "disabledeletenotify"]

            mock_execute_process.return_value = ("fake out", "fake err", 0)

            self._winutils.enable_trim(True)
            mock_execute_process.assert_called_with(args + ["0"])

            self._winutils.enable_trim(False)
            mock_execute_process.assert_called_with(args + ["1"])

    def test_trim(self):
        self._test_trim(err=False)

    def test_trim_exception(self):
        self._test_trim(err=True)

    def _test_rename_user(self, exc=None):
        new_username = "new username"
        user_info = {
            "name": new_username,
        }
        userset_mock = self._win32net_mock.NetUserSetInfo
        if exc:
            userset_mock.side_effect = [exc]
            error_class = (
                exception.ItemNotFoundException if
                exc.args[0] == self._winutils.NERR_UserNotFound else
                exception.CloudbaseInitException)
            with self.assertRaises(error_class):
                self._winutils.rename_user(self._USERNAME, new_username)
            return
        self._winutils.rename_user(self._USERNAME, new_username)
        userset_mock.assert_called_once_with(
            None, self._USERNAME, 0, user_info)

    def test_rename_user(self):
        self._test_rename_user()

    def test_rename_user_item_not_found(self):
        exc = self._win32net_mock.error(self._winutils.NERR_UserNotFound,
                                        *([mock.Mock()] * 2))
        self._test_rename_user(exc=exc)

    def test_rename_user_failed(self):
        exc = self._win32net_mock.error(*([mock.Mock()] * 3))
        self._test_rename_user(exc=exc)

    def _test_enum_users(self, resume_handle=False, exc=None):
        userenum_mock = self._win32net_mock.NetUserEnum

        if exc is not None:
            userenum_mock.side_effect = [exc]
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.enum_users()
            return
        else:
            userenum_mock.side_effect = (
                [([{"name": "fake name"}], mock.sentinel, False)] * 3 +
                [([{"name": "fake name"}], mock.sentinel, resume_handle)])
            self._winutils.enum_users()

        result = self._winutils.enum_users()
        if resume_handle:
            self.assertEqual(result, ["fake name"] * 3)

    def test_enum_users_exception(self):
        exc = self._win32net_mock.error(self._win32net_mock.error,
                                        *([mock.Mock()] * 2))
        self._test_enum_users(exc=exc)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_user_info')
    def _test_set_user_info(self, mock_user_info, full_name=None,
                            disabled=False, expire_interval=None, exc=None):
        user_info = {
            "username": self._USERNAME,
            "full_name": 'fake user',
            "flags": 0,
            "expire_interval": self._win32netcon_mock.TIMEQ_FOREVER
        }
        if full_name:
            user_info["full_name"] = full_name
        if expire_interval:
            user_info["acct_expires"] = expire_interval

        if disabled:
            user_info["flags"] |= self._win32netcon_mock.UF_ACCOUNTDISABLE
        else:
            user_info["flags"] &= self._win32netcon_mock.UF_ACCOUNTDISABLE

        mock_user_info.return_value = user_info
        userset_mock = self._win32net_mock.NetUserSetInfo

        if exc:
            userset_mock.side_effect = [exc]
            error_class = (
                exception.ItemNotFoundException if
                exc.args[0] == self._winutils.NERR_UserNotFound else
                exception.CloudbaseInitException)
            with self.assertRaises(error_class):
                self._winutils.set_user_info(self._USERNAME, full_name, True,
                                             expire_interval)
            return

        self._winutils.set_user_info(self._USERNAME, full_name, True,
                                     expire_interval)
        userset_mock.assert_called_once_with(
            None, self._USERNAME, 2, user_info)

    def test_set_user_info(self):
        self._test_set_user_info()

    def test_set_user_info_full_options(self):
        self._test_set_user_info(full_name='fake_user1',
                                 disabled=True, expire_interval=1)

    def test_set_user_info_not_found(self):
        exc = self._win32net_mock.error(self._winutils.NERR_UserNotFound,
                                        *([mock.Mock()] * 2))
        self._test_set_user_info(full_name='fake_user1',
                                 disabled=True, expire_interval=1,
                                 exc=exc)

    def test_set_user_info_failed(self):
        exc = self._win32net_mock.error(*([mock.Mock()] * 3))
        self._test_set_user_info(exc=exc)

    def test_enum_users(self):
        self._test_enum_users(resume_handle=False)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.get_user_sid')
    def _test_is_builtin_admin(self, mock_get_user_sid, sid_exists,
                               sid_startswith, sid_endswith):
        mock_sid = mock.Mock()
        mock_sid.startswith.return_value = sid_startswith
        mock_sid.endswith.return_value = sid_endswith
        if sid_exists:
            mock_get_user_sid.return_value = mock_sid
        else:
            mock_get_user_sid.return_value = False
        expected_result = sid_exists and sid_startswith and sid_endswith

        result = self._winutils.is_builtin_admin(mock.sentinel)
        self.assertEqual(result, expected_result)

    def test_is_builtin_admin_no_sid(self):
        self._test_is_builtin_admin(sid_exists=False,
                                    sid_startswith=True, sid_endswith=True)

    def test_is_builtin_admin_sid_no_startswith(self):
        self._test_is_builtin_admin(sid_exists=True,
                                    sid_startswith=False, sid_endswith=True)

    def test_is_builtin_admin_sid_no_endswith(self):
        self._test_is_builtin_admin(sid_exists=True,
                                    sid_startswith=True, sid_endswith=False)

    def test_is_builtin_admin(self):
        self._test_is_builtin_admin(sid_exists=True,
                                    sid_startswith=True, sid_endswith=True)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                'execute_system32_process')
    def _test_set_path_admin_acls(self, mock_execute_system32_process,
                                  ret_val=None):
        mock_path = mock.sentinel.path
        expected_logging = ["Assigning admin ACLs on path: %s" % mock_path]
        expected_call = [
            "icacls.exe", mock_path, "/inheritance:r", "/grant:r",
            "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]
        mock_execute_system32_process.return_value = (
            mock.sentinel.out,
            mock.sentinel.err,
            ret_val)
        with self.snatcher:
            if ret_val:
                self.assertRaises(
                    exception.CloudbaseInitException,
                    self._winutils.set_path_admin_acls,
                    mock_path)
            else:
                self._winutils.set_path_admin_acls(mock_path)
        self.assertEqual(self.snatcher.output, expected_logging)
        mock_execute_system32_process.assert_called_once_with(expected_call)

    def test_test_set_path_admin_acls(self):
        self._test_set_path_admin_acls()

    def test_test_set_path_admin_acls_fail(self):
        self._test_set_path_admin_acls(ret_val=1)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                'execute_system32_process')
    def _test_take_path_ownership(self, mock_execute_system32_process,
                                  ret_val=None, username=None):
        mock_path = mock.sentinel.path
        expected_logging = ["Taking ownership of path: %s" % mock_path]
        expected_call = ["takeown.exe", "/F", mock_path]
        mock_execute_system32_process.return_value = (
            mock.sentinel.out,
            mock.sentinel.err,
            ret_val)
        if username:
            self.assertRaises(
                NotImplementedError, self._winutils.take_path_ownership,
                mock_path, username)
            return
        with self.snatcher:
            if ret_val:
                self.assertRaises(
                    exception.CloudbaseInitException,
                    self._winutils.take_path_ownership,
                    mock_path, username)
            else:
                self._winutils.take_path_ownership(mock_path, username)
        self.assertEqual(self.snatcher.output, expected_logging)
        mock_execute_system32_process.assert_called_once_with(expected_call)

    def test_take_path_ownership_username(self):
        self._test_take_path_ownership(username="fake")

    def test_take_path_ownership_fail(self):
        self._test_take_path_ownership(ret_val=1)

    def test_take_path_ownership(self):
        self._test_take_path_ownership()

    def _test_check_dotnet_is_installed(self, version):
        if str(version) != "4":
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.check_dotnet_is_installed,
                              version)
            return
        res = self._winutils.check_dotnet_is_installed(version)
        key = self._winreg_mock.OpenKey.return_value.__enter__.return_value
        self._winreg_mock.OpenKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            'SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\'
            'v%s\\Full' % version)
        self._winreg_mock.QueryValueEx.assert_called_with(
            key, 'Install')
        self.assertTrue(res)

    def test_check_dotnet_is_installed_not_v4(self):
        fake_version = 1
        self._test_check_dotnet_is_installed(fake_version)

    def test_check_dotnet_is_installed_v4(self):
        fake_version = 4
        self._test_check_dotnet_is_installed(fake_version)

    def test_get_file_version(self):
        mock_path = mock.sentinel.fake_path
        mock_info = mock.MagicMock()
        self._win32api_mock.GetFileVersionInfo.return_value = mock_info
        res = self._winutils.get_file_version(mock_path)
        self._win32api_mock.GetFileVersionInfo.assert_called_once_with(
            mock_path, '\\')
        self.assertIsNotNone(res)

    @mock.patch('cloudbaseinit.utils.windows.netlbfo.NetLBFOTeamManager')
    def test_get_network_team_manager(self, mock_netlbfo_team_manager):
        mock_netlbfo_team_manager.is_available.return_value = True
        self.assertEqual(
            mock_netlbfo_team_manager.return_value,
            self._winutils._get_network_team_manager())

    @mock.patch('cloudbaseinit.utils.windows.netlbfo.NetLBFOTeamManager')
    def test_get_network_team_manager_not_found(self,
                                                mock_netlbfo_team_manager):
        mock_netlbfo_team_manager.is_available.return_value = False
        self.assertRaises(
            exception.ItemNotFoundException,
            self._winutils._get_network_team_manager)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                '_get_network_team_manager')
    def test_create_network_team(self, mock_get_network_team_manager):
        mock_team_manager = mock_get_network_team_manager.return_value

        self._winutils.create_network_team(
            mock.sentinel.team_name, mock.sentinel.mode,
            mock.sentinel.lb_algo, mock.sentinel.members,
            mock.sentinel.mac, mock.sentinel.primary_name,
            mock.sentinel.vlan_id, mock.sentinel.lacp_timer)

        mock_team_manager.create_team.assert_called_once_with(
            mock.sentinel.team_name, mock.sentinel.mode,
            mock.sentinel.lb_algo, mock.sentinel.members,
            mock.sentinel.mac, mock.sentinel.primary_name,
            mock.sentinel.vlan_id, mock.sentinel.lacp_timer)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                '_get_network_team_manager')
    def test_add_network_team_nic(self, mock_get_network_team_manager):
        mock_team_manager = mock_get_network_team_manager.return_value

        self._winutils.add_network_team_nic(
            mock.sentinel.team_name, mock.sentinel.nic_name,
            mock.sentinel.vlan_id)

        mock_team_manager.add_team_nic.assert_called_once_with(
            mock.sentinel.team_name, mock.sentinel.nic_name,
            mock.sentinel.vlan_id)
