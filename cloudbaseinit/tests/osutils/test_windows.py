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
        self._win32com_mock = mock.MagicMock()
        self._win32process_mock = mock.MagicMock()
        self._win32security_mock = mock.MagicMock()
        self._win32net_mock = mock.MagicMock()
        self._win32netcon_mock = mock.MagicMock()
        self._win32service_mock = mock.MagicMock()
        self._winerror_mock = mock.MagicMock()
        self._winerror_mock.ERROR_SERVICE_DOES_NOT_EXIST = 0x424
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
            {'win32com': self._win32com_mock,
             'win32process': self._win32process_mock,
             'win32security': self._win32security_mock,
             'win32net': self._win32net_mock,
             'win32netcon': self._win32netcon_mock,
             'win32service': self._win32service_mock,
             'winerror': self._winerror_mock,
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
                self._ctypes_mock.addressof.return_value, 1)

            self._ctypes_mock.addressof.assert_called_once_with(lmi)
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
    def _test_create_user_logon_session(self, mock_Win32_PROFILEINFO, logon,
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
                    "Cannot load user profile: %r", last_error):
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
        self.assertEqual([(mock_response.Name, mock_response.MACAddress)],
                         response)

    def test_get_network_adapters(self):
        self._test_get_network_adapters(False)

    def test_get_network_adapters_xp_2003(self):
        self._test_get_network_adapters(True)

    def _test_set_static_network_config(self, adapter=True, static_val=(0,),
                                        gateway_val=(0,), dns_val=(0,)):
        conn = self._wmi_mock.WMI
        mac_address = '54:EE:75:19:F4:61'
        address = '10.10.10.10'
        broadcast = '0.0.0.0'
        dns_list = ['8.8.8.8']
        set_static_call = functools.partial(
            self._winutils.set_static_network_config,
            mac_address, address, self._NETMASK,
            broadcast, self._GATEWAY, dns_list
        )

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

        conn.return_value.query.return_value = adapter
        adapter_config = adapter[0].associators.return_value[0]
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

            select = ("SELECT * FROM Win32_NetworkAdapter WHERE "
                      "MACAddress = '{}'".format(mac_address))
            conn.return_value.query.assert_called_once_with(select)
            adapter[0].associators.assert_called_with(
                wmi_result_class='Win32_NetworkAdapterConfiguration')
            adapter_config.EnableStatic.assert_called_with(
                [address], [self._NETMASK])
            adapter_config.SetGateways.assert_called_with(
                [self._GATEWAY], [1])
            adapter_config.SetDNSServerSearchOrder.assert_called_with(
                dns_list)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_os_version')
    @mock.patch("cloudbaseinit.utils.windows.network"
                ".get_adapter_addresses")
    def _test_set_static_network_config_v6(self, mock_get_adapter_addresses,
                                           mock_check_os_version,
                                           v6adapters=True, v6error=False):
        friendly_name = "Ethernet0"
        interface_index = "4"
        mac_address = '54:EE:75:19:F4:61'
        address6 = "2001:db8::3"
        netmask6 = "64"
        gateway6 = "2001:db8::1"

        conn = self._wmi_mock.WMI
        netip = conn.return_value.query.return_value[0]
        if v6error:
            netip.Create.side_effect = WMIError
        adapter_addresses = []
        if v6adapters:
            adapter_addresses = [
                {
                    "mac_address": mac_address,
                    "friendly_name": friendly_name,
                    "interface_index": interface_index
                }
            ]
        mock_get_adapter_addresses.return_value = adapter_addresses
        mock_check_os_version.return_value = True

        set_static_call = functools.partial(
            self._winutils.set_static_network_config_v6,
            mac_address, address6, netmask6, gateway6)
        expected_log = []
        if not mock_check_os_version.return_value:
            expected_log.append("Setting IPv6 info not available "
                                "on this system")

        if not v6adapters or v6error:
            self.assertRaises(
                exception.CloudbaseInitException,
                set_static_call)
        else:
            expected_log.append("Setting IPv6 info for %s" % friendly_name)
            with self.snatcher:
                set_static_call()
            mock_get_adapter_addresses.assert_called_once_with()
            select = ("SELECT * FROM MSFT_NetIPAddress "
                      "WHERE InterfaceAlias = '{}'".format(friendly_name))
            conn.return_value.query.assert_called_once_with(select)
            params = {
                "InterfaceIndex": interface_index,
                "InterfaceAlias": friendly_name,
                "IPAddress": address6,
                "AddressFamily": self.windows_utils.AF_INET6,
                "PrefixLength": netmask6,
                # Manual set type.
                "Type": self.windows_utils.UNICAST,
                "PrefixOrigin": self.windows_utils.MANUAL,
                "SuffixOrigin": self.windows_utils.MANUAL,
                "AddressState": self.windows_utils.PREFERRED_ADDR,
                # No expiry.
                "ValidLifetime": None,
                "PreferredLifetime": None,
                "SkipAsSource": False,
                "DefaultGateway": gateway6,
                "PolicyStore": None,
                "PassThru": False,
            }
            netip.Create.assert_called_once_with(**params)
            self.assertEqual(expected_log, self.snatcher.output)

    def test_set_static_network_config(self):
        ret_val1 = (1,)
        ret_val2 = (1,)
        ret_val3 = (0,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2,
                                             dns_val=ret_val3)

    def test_set_static_network_config_query_fail(self):
        self._test_set_static_network_config(adapter=False)

    def test_set_static_network_config_cannot_set_ip(self):
        ret_val1 = (2,)
        self._test_set_static_network_config(static_val=ret_val1)

    def test_set_static_network_config_cannot_set_gateway(self):
        ret_val1 = (1,)
        ret_val2 = (2,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2)

    def test_set_static_network_config_cannot_set_DNS(self):
        ret_val1 = (1,)
        ret_val2 = (1,)
        ret_val3 = (2,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2,
                                             dns_val=ret_val3)

    def test_set_static_network_config_no_reboot(self):
        ret_val1 = (0,)
        ret_val2 = (0,)
        ret_val3 = (0,)
        self._test_set_static_network_config(static_val=ret_val1,
                                             gateway_val=ret_val2,
                                             dns_val=ret_val3)

    def test_set_static_network_config_v6(self):
        self._test_set_static_network_config_v6()

    def test_set_static_network_config_v6_no_adapters(self):
        self._test_set_static_network_config_v6(v6adapters=False)

    def test_set_static_network_config_v6_error(self):
        self._test_set_static_network_config_v6(v6error=True)

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

    def test_get_service(self):
        conn = self._wmi_mock.WMI
        conn.return_value.Win32_Service.return_value = ['fake name']

        response = self._winutils._get_service('fake name')

        conn.assert_called_with(moniker='//./root/cimv2')
        conn.return_value.Win32_Service.assert_called_with(Name='fake name')
        self.assertEqual('fake name', response)

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
                '._get_service')
    def test_get_service_status(self, mock_get_service):
        mock_service = mock.MagicMock()
        mock_get_service.return_value = mock_service

        response = self._winutils.get_service_status('fake name')

        self.assertEqual(mock_service.State, response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service')
    def test_get_service_start_mode(self, mock_get_service):
        mock_service = mock.MagicMock()
        mock_get_service.return_value = mock_service

        response = self._winutils.get_service_start_mode('fake name')

        self.assertEqual(mock_service.StartMode, response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service')
    def _test_set_service_start_mode(self, mock_get_service, ret_val):
        mock_service = mock.MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.ChangeStartMode.return_value = (ret_val,)

        if ret_val != 0:
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.set_service_start_mode,
                              'fake name', 'fake mode')
        else:
            self._winutils.set_service_start_mode('fake name', 'fake mode')

        mock_service.ChangeStartMode.assert_called_once_with('fake mode')

    def test_set_service_start_mode(self):
        self._test_set_service_start_mode(ret_val=0)

    def test_set_service_start_mode_exception(self):
        self._test_set_service_start_mode(ret_val=1)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service')
    def _test_start_service(self, mock_get_service, ret_val):
        mock_service = mock.MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.StartService.return_value = (ret_val,)

        if ret_val != 0:
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.start_service,
                              'fake name')
        else:
            with self.snatcher:
                self._winutils.start_service('fake name')
            self.assertEqual(["Starting service fake name"],
                             self.snatcher.output)

        mock_service.StartService.assert_called_once_with()

    def test_start_service(self):
        self._test_set_service_start_mode(ret_val=0)

    def test_start_service_exception(self):
        self._test_set_service_start_mode(ret_val=1)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service')
    def _test_stop_service(self, mock_get_service, ret_val):
        mock_service = mock.MagicMock()
        mock_get_service.return_value = mock_service
        mock_service.StopService.return_value = (ret_val,)

        if ret_val != 0:
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.stop_service,
                              'fake name')
        else:
            with self.snatcher:
                self._winutils.stop_service('fake name')
            self.assertEqual(["Stopping service fake name"],
                             self.snatcher.output)

        mock_service.StopService.assert_called_once_with()

    def test_stop_service(self):
        self._test_stop_service(ret_val=0)

    def test_stop_service_exception(self):
        self._test_stop_service(ret_val=1)

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

    def _test_get_logical_drives(self, buf_length, last_error=None):
        mock_buf = mock.MagicMock()
        mock_buf.__getitem__.side_effect = ['1', '\x00']
        mock_get_drives = self._windll_mock.kernel32.GetLogicalDriveStringsW

        self._ctypes_mock.create_unicode_buffer.return_value = mock_buf
        mock_get_drives.return_value = buf_length

        if buf_length is None:
            with self.assert_raises_windows_message(
                    "GetLogicalDriveStringsW failed: %r", last_error):
                self._winutils._get_logical_drives()
        else:
            response = self._winutils._get_logical_drives()

            self._ctypes_mock.create_unicode_buffer.assert_called_with(261)
            mock_get_drives.assert_called_with(260, mock_buf)
            self.assertEqual(['1'], response)

    def test_get_logical_drives_exception(self):
        self._test_get_logical_drives(buf_length=None, last_error=100)

    def test_get_logical_drives(self):
        self._test_get_logical_drives(buf_length=2)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils.'
                '_get_logical_drives')
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
        net_addr["mac_address"] = 'fake mac address'
        net_addr["dhcp_server"] = 'fake dhcp server'
        net_addr["dhcp_enabled"] = True
        mock_get_adapter_addresses.return_value = [net_addr]

        response = self._winutils.get_dhcp_hosts_in_use()

        mock_get_adapter_addresses.assert_called_once_with()
        self.assertEqual([('fake mac address', 'fake dhcp server')], response)

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

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.execute_process')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_system_dir')
    @mock.patch("cloudbaseinit.utils.windows.network."
                "get_adapter_addresses")
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '.check_os_version')
    def _test_set_network_adapter_mtu(self,
                                      mock_check_os_version,
                                      mock_get_adapter_addresses,
                                      mock_get_system_dir,
                                      mock_execute_process,
                                      fail=False, os_version_ret=True,
                                      mac_address_match=True,
                                      execute_process_val=0):
        mac_address = "fake mac"
        mtu = "fake mtu"
        base_dir = "fake path"
        mock_check_os_version.return_value = os_version_ret
        mock_get_adapter_addresses.return_value = [mock.MagicMock()
                                                   for _ in range(3)]
        if mac_address_match:
            # Same as `iface_index` under the "interface_index" key.
            mock_get_adapter_addresses.return_value[1].\
                __getitem__.return_value = mac_address
        mock_get_system_dir.return_value = base_dir
        mock_execute_process.return_value = [None, None, execute_process_val]

        if fail:
            with self.assertRaises(exception.CloudbaseInitException):
                self._winutils.set_network_adapter_mtu(mac_address, mtu)
            return

        with self.snatcher:
            self._winutils.set_network_adapter_mtu(mac_address, mtu)
        expected_log = ['Setting MTU for interface "%(mac_address)s" with '
                        'value "%(mtu)s"' %
                        {'mac_address': mac_address, 'mtu': mtu}]
        args = [os.path.join(base_dir, "netsh.exe"),
                "interface", "ipv4", "set", "subinterface",
                mac_address, "mtu=%s" % mtu, "store=persistent"]
        self.assertEqual(expected_log, self.snatcher.output)
        mock_check_os_version.assert_called_once_with(6, 0)
        mock_get_adapter_addresses.assert_called_once_with()
        mock_get_system_dir.assert_called_once_with()
        mock_execute_process.assert_called_once_with(args, shell=False)

    def test_set_network_adapter_mtu_not_supported(self):
        self._test_set_network_adapter_mtu(fail=True, os_version_ret=False)

    def test_set_network_adapter_mtu_no_mac_match(self):
        self._test_set_network_adapter_mtu(fail=True,
                                           mac_address_match=False)

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
