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
import unittest.mock as mock

from cloudbaseinit import exception as cbinit_exception


class WindowsNetworkUtilsTests(unittest.TestCase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()
        self._winreg_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._ctypes_mock,
             'winreg': self._winreg_mock})

        self._module_patcher.start()

        self.network = importlib.import_module(
            'cloudbaseinit.utils.windows.network')

        self.network.iphlpapi = mock.MagicMock()
        self.network.kernel32 = mock.MagicMock()
        self.network.ws2_32 = mock.MagicMock()

    def tearDown(self):
        self._module_patcher.stop()

    def test_format_mac_address(self):
        phys_address = [00, 00, 00, 00]
        response = self.network._format_mac_address(phys_address=phys_address,
                                                    phys_address_len=4)
        self.assertEqual("00:00:00:00", response)

    def _test_socket_addr_to_str(self, ret_val):
        mock_socket_addr = mock.MagicMock()

        mock_create_unicode_buffer = self._ctypes_mock.create_unicode_buffer
        mock_byref = self._ctypes_mock.byref

        self.network.ws2_32.WSAAddressToStringW.return_value = ret_val

        if ret_val:
            self.assertRaises(cbinit_exception.CloudbaseInitException,
                              self.network._socket_addr_to_str,
                              mock_socket_addr)
            self.network.ws2_32.WSAGetLastError.assert_called_once_with()
        else:
            response = self.network._socket_addr_to_str(mock_socket_addr)
            self.assertEqual(mock_create_unicode_buffer.return_value.value,
                             response)

        self._ctypes_mock.wintypes.DWORD.assert_called_once_with(256)
        mock_create_unicode_buffer.assert_called_once_with(256)

        self.network.ws2_32.WSAAddressToStringW.assert_called_once_with(
            mock_socket_addr.lpSockaddr, mock_socket_addr.iSockaddrLength,
            None, mock_create_unicode_buffer.return_value,
            mock_byref.return_value)

        mock_byref.assert_called_once_with(
            self._ctypes_mock.wintypes.DWORD.return_value)

    def test_socket_addr_to_str(self):
        self._test_socket_addr_to_str(ret_val=None)

    def test_socket_addr_to_str_fail(self):
        self._test_socket_addr_to_str(ret_val=1)

    def _test_get_registry_dhcp_server(self, dhcp_server, exception=None):
        fake_adapter = mock.sentinel.fake_adapter_name
        self._winreg_mock.QueryValueEx.return_value = [dhcp_server]

        if exception:
            self._winreg_mock.QueryValueEx.side_effect = [exception]

            if exception.errno != 2:
                self.assertRaises(cbinit_exception.CloudbaseInitException,
                                  self.network._get_registry_dhcp_server,
                                  fake_adapter)
        else:
            response = self.network._get_registry_dhcp_server(fake_adapter)
            if dhcp_server == "255.255.255.255":
                self.assertEqual(None, response)
            else:
                self.assertEqual(dhcp_server, response)

            self._winreg_mock.OpenKey.assert_called_once_with(
                self._winreg_mock.HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\"
                "Interfaces\\%s" % fake_adapter, 0,
                self._winreg_mock.KEY_READ)

            self._winreg_mock.QueryValueEx.assert_called_once_with(
                self._winreg_mock.OpenKey.return_value.__enter__(),
                "DhcpServer")

    def test_get_registry_dhcp_server(self):
        self._test_get_registry_dhcp_server(
            dhcp_server=mock.sentinel.dhcp_server)

    def test_get_registry_dhcp_server_expected(self):
        self._test_get_registry_dhcp_server(dhcp_server="255.255.255.255")

    def test_get_registry_dhcp_server_expeption_not_found(self):
        ex = cbinit_exception.CloudbaseInitException()
        ex.errno = 2
        self._test_get_registry_dhcp_server(dhcp_server="", exception=ex)

    def test_get_registry_dhcp_server_expeption_other(self):
        ex = cbinit_exception.CloudbaseInitException()
        ex.errno = 3
        self._test_get_registry_dhcp_server(dhcp_server="", exception=ex)

    @mock.patch('cloudbaseinit.utils.windows.network._format_mac_address')
    @mock.patch('cloudbaseinit.utils.windows.network._socket_addr_to_str')
    @mock.patch('cloudbaseinit.utils.windows.network'
                '._get_registry_dhcp_server')
    def _test_get_adapter_addresses(self, mock_get_registry_dhcp_server,
                                    mock_socket_addr_to_str,
                                    mock_format_mac_address,
                                    ret_val, p, ret_val2, xp_data_length):
        self.maxDiff = None

        mock_byref = self._ctypes_mock.byref
        mock_cast = self._ctypes_mock.cast
        mock_POINTER = self._ctypes_mock.POINTER

        self.network.iphlpapi.GetAdaptersAddresses.side_effect = [ret_val,
                                                                  ret_val2]
        self.network.kernel32.HeapAlloc.return_value = p
        self.network.iphlpapi.IP_ADAPTER_DHCP_ENABLED = True
        self.network.iphlpapi.IP_ADAPTER_IPV4_ENABLED = True
        self.network.iphlpapi.IP_ADAPTER_ADDRESSES_SIZE_2003 = xp_data_length

        p_curr_addr = mock.MagicMock()

        compare_cast = []
        net_adapters = []
        compare_socket_addr_to_str = []

        mock_cast.side_effect = [p_curr_addr, None, None]
        curr_addr = p_curr_addr.contents
        curr_addr.Flags = True
        curr_addr.Union1.Struct1.Length = 2
        curr_addr.Dhcpv4Server.iSockaddrLength = True

        p_unicast_addr = curr_addr.FirstUnicastAddress
        unicast_addr = p_unicast_addr.contents
        unicast_addresses = [
            (mock_socket_addr_to_str.return_value,
             unicast_addr.Address.lpSockaddr.contents.sa_family)]

        filter_flags = (self.network.iphlpapi.GAA_FLAG_SKIP_ANYCAST |
                        self.network.iphlpapi.GAA_FLAG_SKIP_MULTICAST)

        compare_GetAdaptersAddresses = [mock.call(
            self.network.ws2_32.AF_UNSPEC,
            filter_flags,
            None, None, mock_byref.return_value)]

        if not p:
            self.assertRaises(cbinit_exception.CloudbaseInitException,
                              self.network.get_adapter_addresses)

        if ret_val2 and ret_val2 != self.network.kernel32.ERROR_NO_DATA:
            self.assertRaises(cbinit_exception.CloudbaseInitException,
                              self.network.get_adapter_addresses)
            compare_cast.append(mock.call(p, mock_POINTER.return_value))

            compare_GetAdaptersAddresses.append(mock.call(
                self.network.ws2_32.AF_UNSPEC,
                filter_flags, None,
                p_curr_addr, mock_byref.return_value))

        else:
            response = self.network.get_adapter_addresses()

            if ret_val == self.network.kernel32.ERROR_NO_DATA:
                self.assertEqual([], response)

            elif ret_val == self.network.kernel32.ERROR_BUFFER_OVERFLOW:
                self.network.kernel32.GetProcessHeap.assert_called_once_with()

                self.network.kernel32.HeapAlloc.assert_called_once_with(
                    self.network.kernel32.GetProcessHeap.return_value, 0,
                    self._ctypes_mock.wintypes.ULONG.return_value.value)

                self.network.ws2_32.init_wsa.assert_called_once_with()
                compare_cast.append(mock.call(p, mock_POINTER.return_value))

                compare_GetAdaptersAddresses.append(mock.call(
                    self.network.ws2_32.AF_UNSPEC,
                    filter_flags, None,
                    p_curr_addr, mock_byref.return_value))

                if ret_val2 == self.network.kernel32.ERROR_NO_DATA:
                    self.assertEqual([], response)

                else:
                    compare_cast.append(mock.call(p_unicast_addr.contents.Next,
                                                  mock_POINTER.return_value))

                    mock_format_mac_address.assert_called_once_with(
                        p_curr_addr.contents.PhysicalAddress,
                        p_curr_addr.contents.PhysicalAddressLength)

                    if not curr_addr.Union1.Struct1.Length <= xp_data_length:
                        dhcp_server = mock_socket_addr_to_str.return_value
                        compare_socket_addr_to_str.append(
                            mock.call(curr_addr.Dhcpv4Server |
                                      curr_addr.Dhcpv6Server))
                    else:
                        dhcp_server = \
                            mock_get_registry_dhcp_server.return_value

                        mock_get_registry_dhcp_server.assert_called_once_with(
                            curr_addr.AdapterName)

                    compare_cast.append(mock.call(curr_addr.Next,
                                                  mock_POINTER.return_value))
                    self.network.kernel32.HeapFree.assert_called_once_with(
                        self.network.kernel32.GetProcessHeap.return_value, 0,
                        p)

                    self.network.ws2_32.WSACleanup.assert_called_once_with()

                    compare_socket_addr_to_str.append(mock.call(
                        unicast_addr.Address))

                    net_adapters.append(
                        {"interface_index": curr_addr.Union1.Struct1.IfIndex,
                         "adapter_name": curr_addr.AdapterName,
                         "friendly_name": curr_addr.FriendlyName,
                         "description": curr_addr.Description,
                         "mtu": curr_addr.Mtu,
                         "mac_address": mock_format_mac_address.return_value,
                         "dhcp_enabled": True,
                         "dhcp_server": dhcp_server,
                         "interface_type": curr_addr.IfType,
                         "unicast_addresses": unicast_addresses})

                    self.assertEqual(net_adapters, response)

        self.assertEqual(compare_cast, mock_cast.call_args_list)

        self.assertEqual(
            compare_GetAdaptersAddresses,
            self.network.iphlpapi.GetAdaptersAddresses.call_args_list)

    def test_get_adapter_addresses_no_data(self):
        self._test_get_adapter_addresses(
            ret_val=self.network.kernel32.ERROR_NO_DATA,
            p=True, ret_val2=self.network.kernel32.ERROR_NO_DATA,
            xp_data_length=3)

    def test_get_adapter_addresses_overflow_and_no_data(self):
        self._test_get_adapter_addresses(
            ret_val=self.network.kernel32.ERROR_BUFFER_OVERFLOW,
            p=True, ret_val2=self.network.kernel32.ERROR_NO_DATA,
            xp_data_length=3)

    def test_get_adapter_addresses_overflow_other_ret_val(self):
        self._test_get_adapter_addresses(
            ret_val=self.network.kernel32.ERROR_BUFFER_OVERFLOW,
            p=True, ret_val2=mock.sentinel.other_return_value,
            xp_data_length=3)

    def test_get_adapter_addresses_overflow(self):
        self._test_get_adapter_addresses(
            ret_val=self.network.kernel32.ERROR_BUFFER_OVERFLOW,
            p=True, ret_val2=None,
            xp_data_length=3)

    def test_get_adapter_addresses_overflow_xp_data(self):
        self._test_get_adapter_addresses(
            ret_val=self.network.kernel32.ERROR_BUFFER_OVERFLOW,
            p=True, ret_val2=None,
            xp_data_length=0)
