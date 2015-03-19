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


import importlib
import os

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo.config import cfg
import six

from cloudbaseinit import exception
from cloudbaseinit.tests import fake
from cloudbaseinit.tests import testutils

CONF = cfg.CONF


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
        self._pywintypes_mock.com_error = fake.FakeComError
        self._win32com_mock = mock.MagicMock()
        self._win32process_mock = mock.MagicMock()
        self._win32security_mock = mock.MagicMock()
        self._wmi_mock = mock.MagicMock()
        self._moves_mock = mock.MagicMock()
        self._xmlrpc_client_mock = mock.MagicMock()
        self._ctypes_mock = mock.MagicMock()
        self._tzlocal_mock = mock.Mock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'win32com': self._win32com_mock,
             'win32process': self._win32process_mock,
             'win32security': self._win32security_mock,
             'wmi': self._wmi_mock,
             'six.moves': self._moves_mock,
             'six.moves.xmlrpc_client': self._xmlrpc_client_mock,
             'ctypes': self._ctypes_mock,
             'pywintypes': self._pywintypes_mock,
             'tzlocal': self._tzlocal_mock})

        self._module_patcher.start()
        self.windows_utils = importlib.import_module(
            "cloudbaseinit.osutils.windows")

        self._winreg_mock = self._moves_mock.winreg
        self._windll_mock = self._ctypes_mock.windll
        self._wintypes_mock = self._ctypes_mock.wintypes
        self._client_mock = self._win32com_mock.client
        self.windows_utils.WindowsError = mock.MagicMock()

        self._winutils = self.windows_utils.WindowsUtils()

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('cloudbaseinit.osutils.windows.privilege')
    def _test_reboot(self, mock_privilege_module, ret_value,
                     expected_ret_value=None):
        mock_privilege_module.acquire_privilege = mock.MagicMock()
        advapi32 = self._windll_mock.advapi32
        advapi32.InitiateSystemShutdownW = mock.MagicMock(
            return_value=ret_value)

        if not ret_value:
            with self.assert_raises_windows_message(
                    "Reboot failed: %r", expected_ret_value):
                self._winutils.reboot()
        else:
            self._winutils.reboot()

            advapi32.InitiateSystemShutdownW.assert_called_with(
                0,
                "Cloudbase-Init reboot",
                0, True, True)
        mock_privilege_module.acquire_privilege.assert_called_once_with(
            self._win32security_mock.SE_SHUTDOWN_NAME)

    def test_reboot(self):
        self._test_reboot(ret_value=True)

    def test_reboot_failed(self):
        self._test_reboot(ret_value=None, expected_ret_value=100)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._sanitize_wmi_input')
    def _test_get_user_wmi_object(self, mock_sanitize_wmi_input, return_value):
        conn = self._wmi_mock.WMI
        mock_sanitize_wmi_input.return_value = self._USERNAME
        conn.return_value.query.return_value = return_value

        response = self._winutils._get_user_wmi_object(self._USERNAME)

        conn.return_value.query.assert_called_with(
            "SELECT * FROM Win32_Account where name = \'%s\'" % self._USERNAME)
        mock_sanitize_wmi_input.assert_called_with(self._USERNAME)
        conn.assert_called_with(moniker='//./root/cimv2')
        if return_value:
            self.assertTrue(response is not None)
        else:
            self.assertTrue(response is None)

    def test_get_user_wmi_object(self):
        caption = 'fake'
        self._test_get_user_wmi_object(return_value=caption)

    def test_no_user_wmi_object(self):
        empty_caption = ''
        self._test_get_user_wmi_object(return_value=empty_caption)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_user_wmi_object')
    def _test_user_exists(self, mock_get_user_wmi_object, return_value):
        mock_get_user_wmi_object.return_value = return_value
        response = self._winutils.user_exists(return_value)
        mock_get_user_wmi_object.assert_called_with(return_value)
        if return_value:
            self.assertTrue(response)
        else:
            self.assertFalse(response)

    def test_user_exists(self):
        self._test_user_exists(return_value=self._USERNAME)

    def test_username_does_not_exist(self):
        self._test_user_exists(return_value=None)

    def test_sanitize_wmi_input(self):
        unsanitised = ' \' '
        response = self._winutils._sanitize_wmi_input(unsanitised)
        sanitised = ' \'\' '
        self.assertEqual(sanitised, response)

    def test_sanitize_shell_input(self):
        unsanitised = ' " '
        response = self._winutils.sanitize_shell_input(unsanitised)
        sanitised = ' \\" '
        self.assertEqual(sanitised, response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._set_user_password_expiration')
    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_adsi_object')
    def _test_create_or_change_user(self, mock_get_adsi_object,
                                    mock_set_user_password_expiration,
                                    create, password_expires, ret_value=0):

        if not ret_value:
            self._winutils._create_or_change_user(self._USERNAME,
                                                  self._PASSWORD, create,
                                                  password_expires)
            mock_set_user_password_expiration.assert_called_with(
                self._USERNAME, password_expires)
        else:
            mock_get_adsi_object.side_effect = [
                self._pywintypes_mock.com_error]
            self.assertRaises(
                exception.CloudbaseInitException,
                self._winutils._create_or_change_user,
                self._USERNAME, self._PASSWORD, create, password_expires)

        if create:
            mock_get_adsi_object.assert_called_with()
        else:
            mock_get_adsi_object.assert_called_with(
                object_name=self._USERNAME, object_type='user')

    def test_create_user_and_add_password_expire_true(self):
        self._test_create_or_change_user(create=True, password_expires=True)

    def test_create_user_and_add_password_expire_false(self):
        self._test_create_or_change_user(create=True, password_expires=False)

    def test_add_password_expire_true(self):
        self._test_create_or_change_user(create=False, password_expires=True)

    def test_add_password_expire_false(self):
        self._test_create_or_change_user(create=False, password_expires=False)

    def test_create_user_and_add_password_expire_true_with_ret_value(self):
        self._test_create_or_change_user(create=True, password_expires=True,
                                         ret_value=1)

    def test_create_user_and_add_password_expire_false_with_ret_value(self):
        self._test_create_or_change_user(create=True,
                                         password_expires=False, ret_value=1)

    def test_add_password_expire_true_with_ret_value(self):
        self._test_create_or_change_user(create=False,
                                         password_expires=True, ret_value=1)

    def test_add_password_expire_false_with_ret_value(self):
        self._test_create_or_change_user(create=False,
                                         password_expires=False, ret_value=1)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_user_wmi_object')
    def _test_set_user_password_expiration(self, mock_get_user_wmi_object,
                                           fake_obj):
        mock_get_user_wmi_object.return_value = fake_obj

        response = self._winutils._set_user_password_expiration(
            self._USERNAME, True)

        if fake_obj:
            self.assertTrue(fake_obj.PasswordExpires)
            self.assertTrue(response)
        else:
            self.assertFalse(response)

    def test_set_password_expiration(self):
        fake = mock.Mock()
        self._test_set_user_password_expiration(fake_obj=fake)

    def test_set_password_expiration_no_object(self):
        self._test_set_user_password_expiration(fake_obj=None)

    def _test_get_user_sid_and_domain(self, ret_val, last_error=None):
        cbSid = mock.Mock()
        sid = mock.Mock()
        size = 1024
        cchReferencedDomainName = mock.Mock()
        domainName = mock.Mock()
        sidNameUse = mock.Mock()
        advapi32 = self._windll_mock.advapi32

        self._ctypes_mock.create_string_buffer.return_value = sid
        self._ctypes_mock.sizeof.return_value = size
        self._wintypes_mock.DWORD.return_value = cchReferencedDomainName
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
                '._get_user_wmi_object')
    def _test_get_user_sid(self, mock_get_user_wmi_object, fail):
        r = mock.Mock()
        if not fail:
            mock_get_user_wmi_object.return_value = None

            response = self._winutils.get_user_sid(self._USERNAME)

            self.assertTrue(response is None)
        else:
            mock_get_user_wmi_object.return_value = r

            response = self._winutils.get_user_sid(self._USERNAME)

            self.assertTrue(response is not None)
        mock_get_user_wmi_object.assert_called_with(self._USERNAME)

    def test_get_user_sid(self):
        self._test_get_user_sid(fail=False)

    def test_get_user_sid_fail(self):
        self._test_get_user_sid(fail=True)

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

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._sanitize_wmi_input')
    def _test_set_static_network_config(self, mock_sanitize_wmi_input,
                                        adapter, ret_val1=None,
                                        ret_val2=None, ret_val3=None):
        conn = self._wmi_mock.WMI
        address = '10.10.10.10'
        mac_address = '54:EE:75:19:F4:61'
        broadcast = '0.0.0.0'
        dns_list = ['8.8.8.8']

        if not adapter:
            self.assertRaises(
                exception.CloudbaseInitException,
                self._winutils.set_static_network_config,
                mac_address, address, self._NETMASK,
                broadcast, self._GATEWAY, dns_list)
        else:
            conn.return_value.query.return_value = adapter
            adapter_config = adapter[0].associators()[0]
            adapter_config.EnableStatic.return_value = ret_val1
            adapter_config.SetGateways.return_value = ret_val2
            adapter_config.SetDNSServerSearchOrder.return_value = ret_val3
            adapter.__len__.return_value = 1

            if ret_val1[0] > 1:
                self.assertRaises(
                    exception.CloudbaseInitException,
                    self._winutils.set_static_network_config,
                    mac_address, address, self._NETMASK,
                    broadcast, self._GATEWAY, dns_list)

            elif ret_val2[0] > 1:
                self.assertRaises(
                    exception.CloudbaseInitException,
                    self._winutils.set_static_network_config,
                    mac_address, address, self._NETMASK,
                    broadcast, self._GATEWAY, dns_list)

            elif ret_val3[0] > 1:
                self.assertRaises(
                    exception.CloudbaseInitException,
                    self._winutils.set_static_network_config,
                    mac_address, address, self._NETMASK,
                    broadcast, self._GATEWAY, dns_list)

            else:
                response = self._winutils.set_static_network_config(
                    mac_address, address, self._NETMASK,
                    broadcast, self._GATEWAY, dns_list)

                if ret_val1[0] or ret_val2[0] or ret_val3[0] == 1:
                    self.assertTrue(response)
                else:
                    self.assertFalse(response)
                adapter_config.EnableStatic.assert_called_with(
                    [address], [self._NETMASK])
                adapter_config.SetGateways.assert_called_with(
                    [self._GATEWAY], [1])
                adapter_config.SetDNSServerSearchOrder.assert_called_with(
                    dns_list)

                adapter[0].associators.assert_called_with(
                    wmi_result_class='Win32_NetworkAdapterConfiguration')
                conn.return_value.query.assert_called_with(
                    "SELECT * FROM Win32_NetworkAdapter WHERE "
                    "MACAddress = '{}'".format(mac_address)
                )

    def test_set_static_network_config(self):
        adapter = mock.MagicMock()
        ret_val1 = (1,)
        ret_val2 = (1,)
        ret_val3 = (0,)
        self._test_set_static_network_config(adapter=adapter,
                                             ret_val1=ret_val1,
                                             ret_val2=ret_val2,
                                             ret_val3=ret_val3)

    def test_set_static_network_config_query_fail(self):
        self._test_set_static_network_config(adapter=None)

    def test_set_static_network_config_cannot_set_ip(self):
        adapter = mock.MagicMock()
        ret_val1 = (2,)
        self._test_set_static_network_config(adapter=adapter,
                                             ret_val1=ret_val1)

    def test_set_static_network_config_cannot_set_gateway(self):
        adapter = mock.MagicMock()
        ret_val1 = (1,)
        ret_val2 = (2,)
        self._test_set_static_network_config(adapter=adapter,
                                             ret_val1=ret_val1,
                                             ret_val2=ret_val2)

    def test_set_static_network_config_cannot_set_DNS(self):
        adapter = mock.MagicMock()
        ret_val1 = (1,)
        ret_val2 = (1,)
        ret_val3 = (2,)
        self._test_set_static_network_config(adapter=adapter,
                                             ret_val1=ret_val1,
                                             ret_val2=ret_val2,
                                             ret_val3=ret_val3)

    def test_set_static_network_config_no_reboot(self):
        adapter = mock.MagicMock()
        ret_val1 = (0,)
        ret_val2 = (0,)
        ret_val3 = (0,)
        self._test_set_static_network_config(adapter=adapter,
                                             ret_val1=ret_val1,
                                             ret_val2=ret_val2,
                                             ret_val3=ret_val3)

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
    def _test_wait_for_boot_completion(self, ret_val, mock_sleep):
        self._winreg_mock.QueryValueEx.side_effect = [ret_val]

        self._winutils.wait_for_boot_completion()

        key = self._winreg_mock.OpenKey.return_value.__enter__.return_value
        self._winreg_mock.OpenKey.assert_called_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            "SYSTEM\\Setup\\Status\\SysprepStatus", 0,
            self._winreg_mock.KEY_READ)

        self._winreg_mock.QueryValueEx.assert_called_with(
            key, "GeneralizationState")

    def test_wait_for_boot_completion(self):
        ret_val = [7]
        self._test_wait_for_boot_completion(ret_val)

    def test_get_service(self):
        conn = self._wmi_mock.WMI
        conn.return_value.Win32_Service.return_value = ['fake name']

        response = self._winutils._get_service('fake name')

        conn.assert_called_with(moniker='//./root/cimv2')
        conn.return_value.Win32_Service.assert_called_with(Name='fake name')
        self.assertEqual('fake name', response)

    @mock.patch('cloudbaseinit.osutils.windows.WindowsUtils'
                '._get_service')
    def test_check_service_exists(self, mock_get_service):
        mock_get_service.return_value = 'not None'

        response = self._winutils.check_service_exists('fake name')

        self.assertTrue(response)

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
            self._winutils.start_service('fake name')

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
            self._winutils.stop_service('fake name')

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

    def _test_check_os_version(self, ret_value, error_value=None):
        self._windll_mock.kernel32.VerSetConditionMask.return_value = 2
        self._windll_mock.kernel32.VerifyVersionInfoW.return_value = ret_value
        self._windll_mock.kernel32.GetLastError.return_value = error_value

        old_version = self._winutils.ERROR_OLD_WIN_VERSION

        if error_value and error_value is not old_version:
            self.assertRaises(exception.CloudbaseInitException,
                              self._winutils.check_os_version, 3, 1, 2)
            self._windll_mock.kernel32.GetLastError.assert_called_once_with()

        else:
            response = self._winutils.check_os_version(3, 1, 2)

            self._ctypes_mock.sizeof.assert_called_once_with(
                self.windows_utils.Win32_OSVERSIONINFOEX_W)
            self.assertEqual(
                3, self._windll_mock.kernel32.VerSetConditionMask.call_count)

            self._windll_mock.kernel32.VerifyVersionInfoW.assert_called_with(
                self._ctypes_mock.byref.return_value, 1 | 2 | 3 | 7, 2)

            if error_value is old_version:
                self._windll_mock.kernel32.GetLastError.assert_called_with()
                self.assertFalse(response)
            else:
                self.assertTrue(response)

    def test_check_os_version(self):
        m = mock.MagicMock()
        self._test_check_os_version(ret_value=m)

    def test_check_os_version_expect_False(self):
        self._test_check_os_version(
            ret_value=None, error_value=self._winutils.ERROR_OLD_WIN_VERSION)

    def test_check_os_version_exception(self):
        self._test_check_os_version(ret_value=None, error_value=9999)

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
                '.get_sysnative_dir')
    @mock.patch('os.path.isdir')
    def test_check_sysnative_dir_exists(self, mock_isdir,
                                        mock_get_sysnative_dir):
        mock_get_sysnative_dir.return_value = 'fake_sysnative'
        mock_isdir.return_value = True

        response = self._winutils.check_sysnative_dir_exists()

        self.assertTrue(response)

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
                                        ret_val):
        mock_check_sysnative_dir_exists.return_value = ret_val
        mock_get_sysnative_dir.return_value = 'fake'
        mock_get_system32_dir.return_value = 'fake'
        fake_path = os.path.join('fake', 'WindowsPowerShell\\v1.0\\'
                                         'powershell.exe')
        args = [fake_path, '-ExecutionPolicy', 'RemoteSigned',
                '-NonInteractive', '-File', 'fake_script_path']

        response = self._winutils.execute_powershell_script(
            script_path='fake_script_path')

        if ret_val is True:
            mock_get_sysnative_dir.assert_called_once_with()
        else:
            mock_get_system32_dir.assert_called_once_with()

        mock_execute_process.assert_called_with(args, shell=False)
        self.assertEqual(mock_execute_process.return_value, response)

    def test_execute_powershell_script_sysnative(self):
        self._test_execute_powershell_script(ret_val=True)

    def test_execute_powershell_script_system32(self):
        self._test_execute_powershell_script(ret_val=False)

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
