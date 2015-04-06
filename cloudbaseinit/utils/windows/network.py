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

import ctypes

from ctypes import wintypes
from six.moves import winreg

from cloudbaseinit import exception
from cloudbaseinit.utils.windows import iphlpapi
from cloudbaseinit.utils.windows import kernel32
from cloudbaseinit.utils.windows import ws2_32


def _format_mac_address(phys_address, phys_address_len):
    mac_address = ""
    for i in range(0, phys_address_len):
        b = phys_address[i]
        if mac_address:
            mac_address += ":"
        mac_address += "%02X" % b
    return mac_address


def _socket_addr_to_str(socket_addr):
    addr_str_len = wintypes.DWORD(256)
    addr_str = ctypes.create_unicode_buffer(256)

    ret_val = ws2_32.WSAAddressToStringW(
        socket_addr.lpSockaddr,
        socket_addr.iSockaddrLength,
        None, addr_str, ctypes.byref(addr_str_len))
    if ret_val:
        raise exception.CloudbaseInitException(
            "WSAAddressToStringW failed: %s" % ws2_32.WSAGetLastError())

    return addr_str.value


def _get_registry_dhcp_server(adapter_name):
    with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\" +
            "Tcpip\\Parameters\\Interfaces\\%s" % adapter_name, 0,
            winreg.KEY_READ) as key:
        try:
            dhcp_server = winreg.QueryValueEx(key, "DhcpServer")[0]
            if dhcp_server == "255.255.255.255":
                dhcp_server = None
            return dhcp_server
        except Exception as ex:
            # Not found
            if ex.errno != 2:
                raise


def get_adapter_addresses():
    net_adapters = []
    filter_flags = (iphlpapi.GAA_FLAG_SKIP_ANYCAST |
                    iphlpapi.GAA_FLAG_SKIP_MULTICAST)

    size = wintypes.ULONG()
    ret_val = iphlpapi.GetAdaptersAddresses(
        ws2_32.AF_UNSPEC,
        filter_flags,
        None, None, ctypes.byref(size))

    if ret_val == kernel32.ERROR_NO_DATA:
        return net_adapters

    if ret_val == kernel32.ERROR_BUFFER_OVERFLOW:
        proc_heap = kernel32.GetProcessHeap()
        p = kernel32.HeapAlloc(proc_heap, 0, size.value)
        if not p:
            raise exception.CloudbaseInitException("Cannot allocate memory")

        ws2_32.init_wsa()

        try:
            p_addr = ctypes.cast(p, ctypes.POINTER(
                iphlpapi.IP_ADAPTER_ADDRESSES))

            ret_val = iphlpapi.GetAdaptersAddresses(
                ws2_32.AF_UNSPEC,
                filter_flags,
                None, p_addr, ctypes.byref(size))

            if ret_val == kernel32.ERROR_NO_DATA:
                return net_adapters

            if ret_val:
                raise exception.CloudbaseInitException(
                    "GetAdaptersAddresses failed: %r" % ret_val)

            p_curr_addr = p_addr
            while p_curr_addr:
                curr_addr = p_curr_addr.contents

                xp_data_only = (curr_addr.Union1.Struct1.Length <=
                                iphlpapi.IP_ADAPTER_ADDRESSES_SIZE_2003)

                mac_address = _format_mac_address(
                    curr_addr.PhysicalAddress,
                    curr_addr.PhysicalAddressLength)

                dhcp_enabled = (
                    curr_addr.Flags & iphlpapi.IP_ADAPTER_DHCP_ENABLED) != 0
                dhcp_server = None

                if dhcp_enabled:
                    if not xp_data_only:
                        if curr_addr.Flags & iphlpapi.IP_ADAPTER_IPV4_ENABLED:
                            dhcp_addr = curr_addr.Dhcpv4Server

                        if ((curr_addr.Flags &
                             iphlpapi.IP_ADAPTER_IPV6_ENABLED) and
                            (not dhcp_addr or
                             not dhcp_addr.iSockaddrLength)):
                            dhcp_addr = curr_addr.Dhcpv6Server

                        if dhcp_addr and dhcp_addr.iSockaddrLength:
                            dhcp_server = _socket_addr_to_str(dhcp_addr)
                    else:
                        dhcp_server = _get_registry_dhcp_server(
                            curr_addr.AdapterName)

                unicast_addresses = []

                p_unicast_addr = curr_addr.FirstUnicastAddress
                while p_unicast_addr:
                    unicast_addr = p_unicast_addr.contents
                    unicast_addresses.append((
                        _socket_addr_to_str(unicast_addr.Address),
                        unicast_addr.Address.lpSockaddr.contents.sa_family))
                    p_unicast_addr = ctypes.cast(
                        unicast_addr.Next,
                        ctypes.POINTER(iphlpapi.IP_ADAPTER_UNICAST_ADDRESS))

                net_adapters.append(
                    {
                        "interface_index": curr_addr.Union1.Struct1.IfIndex,
                        "adapter_name": curr_addr.AdapterName,
                        "friendly_name": curr_addr.FriendlyName,
                        "description": curr_addr.Description,
                        "mtu": curr_addr.Mtu,
                        "mac_address": mac_address,
                        "dhcp_enabled": dhcp_enabled,
                        "dhcp_server": dhcp_server,
                        "interface_type": curr_addr.IfType,
                        "unicast_addresses": unicast_addresses
                    })

                p_curr_addr = ctypes.cast(
                    curr_addr.Next, ctypes.POINTER(
                        iphlpapi.IP_ADAPTER_ADDRESSES))

        finally:
            kernel32.HeapFree(proc_heap, 0, p)
            ws2_32.WSACleanup()

    return net_adapters
