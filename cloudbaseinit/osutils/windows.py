# Copyright 2012 Cloudbase Solutions Srl
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
import ctypes
from ctypes import wintypes
import os
import re
import struct
import time

from oslo_log import log as oslo_logging
import pywintypes
import six
from six.moves import winreg
from tzlocal import windows_tz
from win32com import client
import win32net
import win32netcon
import win32process
import win32security
import win32service
import winerror
import wmi

from cloudbaseinit import exception
from cloudbaseinit.osutils import base
from cloudbaseinit.utils.windows import disk
from cloudbaseinit.utils.windows import network
from cloudbaseinit.utils.windows import privilege
from cloudbaseinit.utils.windows import timezone


LOG = oslo_logging.getLogger(__name__)
AF_INET6 = 23
UNICAST = 1
MANUAL = 1
PREFERRED_ADDR = 4

advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32
netapi32 = ctypes.windll.netapi32
userenv = ctypes.windll.userenv
iphlpapi = ctypes.windll.iphlpapi
Ws2_32 = ctypes.windll.Ws2_32
setupapi = ctypes.windll.setupapi
msvcrt = ctypes.cdll.msvcrt
ntdll = ctypes.windll.ntdll


class Win32_PROFILEINFO(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('lpUserName', wintypes.LPWSTR),
        ('lpProfilePath', wintypes.LPWSTR),
        ('lpDefaultPath', wintypes.LPWSTR),
        ('lpServerName', wintypes.LPWSTR),
        ('lpPolicyPath', wintypes.LPWSTR),
        ('hprofile', wintypes.HANDLE)
    ]


class Win32_LOCALGROUP_MEMBERS_INFO_3(ctypes.Structure):
    _fields_ = [
        ('lgrmi3_domainandname', wintypes.LPWSTR)
    ]


class Win32_MIB_IPFORWARDROW(ctypes.Structure):
    _fields_ = [
        ('dwForwardDest', wintypes.DWORD),
        ('dwForwardMask', wintypes.DWORD),
        ('dwForwardPolicy', wintypes.DWORD),
        ('dwForwardNextHop', wintypes.DWORD),
        ('dwForwardIfIndex', wintypes.DWORD),
        ('dwForwardType', wintypes.DWORD),
        ('dwForwardProto', wintypes.DWORD),
        ('dwForwardAge', wintypes.DWORD),
        ('dwForwardNextHopAS', wintypes.DWORD),
        ('dwForwardMetric1', wintypes.DWORD),
        ('dwForwardMetric2', wintypes.DWORD),
        ('dwForwardMetric3', wintypes.DWORD),
        ('dwForwardMetric4', wintypes.DWORD),
        ('dwForwardMetric5', wintypes.DWORD)
    ]


class Win32_MIB_IPFORWARDTABLE(ctypes.Structure):
    _fields_ = [
        ('dwNumEntries', wintypes.DWORD),
        ('table', Win32_MIB_IPFORWARDROW * 1)
    ]


class Win32_OSVERSIONINFOEX_W(ctypes.Structure):
    _fields_ = [
        ('dwOSVersionInfoSize', wintypes.DWORD),
        ('dwMajorVersion', wintypes.DWORD),
        ('dwMinorVersion', wintypes.DWORD),
        ('dwBuildNumber', wintypes.DWORD),
        ('dwPlatformId', wintypes.DWORD),
        ('szCSDVersion', wintypes.WCHAR * 128),
        ('wServicePackMajor', wintypes.WORD),
        ('wServicePackMinor', wintypes.WORD),
        ('wSuiteMask', wintypes.WORD),
        ('wProductType', wintypes.BYTE),
        ('wReserved', wintypes.BYTE)
    ]


class Win32_SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('InterfaceClassGuid', disk.GUID),
        ('Flags', wintypes.DWORD),
        ('Reserved', ctypes.POINTER(wintypes.ULONG))
    ]


class Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('DevicePath', ctypes.c_byte * 2)
    ]


class Win32_STORAGE_DEVICE_NUMBER(ctypes.Structure):
    _fields_ = [
        ('DeviceType', wintypes.DWORD),
        ('DeviceNumber', wintypes.DWORD),
        ('PartitionNumber', wintypes.DWORD)
    ]


msvcrt.malloc.argtypes = [ctypes.c_size_t]
msvcrt.malloc.restype = ctypes.c_void_p

msvcrt.free.argtypes = [ctypes.c_void_p]
msvcrt.free.restype = None

ntdll.RtlVerifyVersionInfo.argtypes = [
    ctypes.POINTER(Win32_OSVERSIONINFOEX_W),
    wintypes.DWORD, wintypes.ULARGE_INTEGER]
ntdll.RtlVerifyVersionInfo.restype = wintypes.DWORD

kernel32.VerSetConditionMask.argtypes = [wintypes.ULARGE_INTEGER,
                                         wintypes.DWORD,
                                         wintypes.BYTE]
kernel32.VerSetConditionMask.restype = wintypes.ULARGE_INTEGER

kernel32.SetComputerNameExW.argtypes = [ctypes.c_int, wintypes.LPCWSTR]
kernel32.SetComputerNameExW.restype = wintypes.BOOL

kernel32.GetLogicalDriveStringsW.argtypes = [wintypes.DWORD, wintypes.LPWSTR]
kernel32.GetLogicalDriveStringsW.restype = wintypes.DWORD

kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
kernel32.GetDriveTypeW.restype = wintypes.UINT

kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.LPVOID,
                                 wintypes.DWORD, wintypes.DWORD,
                                 wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE

kernel32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.DWORD),
                                     wintypes.LPVOID]
kernel32.DeviceIoControl.restype = wintypes.BOOL

kernel32.GetProcessHeap.argtypes = []
kernel32.GetProcessHeap.restype = wintypes.HANDLE

kernel32.HeapAlloc.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                               ctypes.c_size_t]
kernel32.HeapAlloc.restype = wintypes.LPVOID

kernel32.HeapFree.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                              wintypes.LPVOID]
kernel32.HeapFree.restype = wintypes.BOOL

iphlpapi.GetIpForwardTable.argtypes = [
    ctypes.POINTER(Win32_MIB_IPFORWARDTABLE),
    ctypes.POINTER(wintypes.ULONG),
    wintypes.BOOL]
iphlpapi.GetIpForwardTable.restype = wintypes.DWORD

Ws2_32.inet_ntoa.restype = ctypes.c_char_p

setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(disk.GUID),
                                          wintypes.LPCWSTR,
                                          wintypes.HANDLE,
                                          wintypes.DWORD]
setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE

setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.POINTER(disk.GUID),
    wintypes.DWORD,
    ctypes.POINTER(Win32_SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL

setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(Win32_SP_DEVICE_INTERFACE_DATA),
    ctypes.POINTER(Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL

setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

VER_MAJORVERSION = 1
VER_MINORVERSION = 2
VER_BUILDNUMBER = 4

VER_GREATER_EQUAL = 3

GUID_DEVINTERFACE_DISK = disk.GUID(0x53f56307, 0xb6bf, 0x11d0, 0x94, 0xf2,
                                   0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b)


class WindowsUtils(base.BaseOSUtils):
    NERR_GroupNotFound = 2220
    NERR_UserNotFound = 2221
    ERROR_ACCESS_DENIED = 5
    ERROR_INSUFFICIENT_BUFFER = 122
    ERROR_NO_DATA = 232
    ERROR_NO_SUCH_MEMBER = 1387
    ERROR_MEMBER_IN_ALIAS = 1378
    ERROR_INVALID_MEMBER = 1388
    ERROR_NO_MORE_FILES = 18

    STATUS_REVISION_MISMATCH = 0xC0000059

    ADS_UF_PASSWORD_EXPIRED = 0x800000
    PASSWORD_CHANGED_FLAG = 1

    INVALID_HANDLE_VALUE = 0xFFFFFFFF

    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2

    OPEN_EXISTING = 3

    IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080

    MAX_PATH = 260

    DIGCF_PRESENT = 2
    DIGCF_DEVICEINTERFACE = 0x10

    DRIVE_CDROM = 5

    SERVICE_STATUS_STOPPED = "Stopped"
    SERVICE_STATUS_START_PENDING = "Start Pending"
    SERVICE_STATUS_STOP_PENDING = "Stop Pending"
    SERVICE_STATUS_RUNNING = "Running"
    SERVICE_STATUS_CONTINUE_PENDING = "Continue Pending"
    SERVICE_STATUS_PAUSE_PENDING = "Pause Pending"
    SERVICE_STATUS_PAUSED = "Paused"
    SERVICE_STATUS_UNKNOWN = "Unknown"

    SERVICE_START_MODE_AUTOMATIC = "Automatic"
    SERVICE_START_MODE_MANUAL = "Manual"
    SERVICE_START_MODE_DISABLED = "Disabled"

    ComputerNamePhysicalDnsHostname = 5

    _config_key = 'SOFTWARE\\Cloudbase Solutions\\Cloudbase-Init\\'
    _service_name = 'cloudbase-init'

    _FW_IP_PROTOCOL_TCP = 6
    _FW_IP_PROTOCOL_UDP = 17
    _FW_SCOPE_ALL = 0
    _FW_SCOPE_LOCAL_SUBNET = 1

    def reboot(self):
        with privilege.acquire_privilege(win32security.SE_SHUTDOWN_NAME):
            ret_val = advapi32.InitiateSystemShutdownExW(
                0, "Cloudbase-Init reboot",
                0, True, True, 0)
            if not ret_val:
                raise exception.WindowsCloudbaseInitException(
                    "Reboot failed: %r")

    def user_exists(self, username):
        try:
            self._get_user_info(username, 1)
            return True
        except exception.ItemNotFoundException:
            # User not found
            return False

    def create_user(self, username, password, password_expires=False):
        user_info = {
            "name": username,
            "password": password,
            "priv": win32netcon.USER_PRIV_USER,
            "flags": win32netcon.UF_NORMAL_ACCOUNT | win32netcon.UF_SCRIPT,
        }

        if not password_expires:
            user_info["flags"] |= win32netcon.UF_DONT_EXPIRE_PASSWD

        try:
            win32net.NetUserAdd(None, 1, user_info)
        except win32net.error as ex:
            raise exception.CloudbaseInitException(
                "Create user failed: %s" % ex.args[2])

    def _get_user_info(self, username, level):
        try:
            return win32net.NetUserGetInfo(None, username, level)
        except win32net.error as ex:
            if ex.args[0] == self.NERR_UserNotFound:
                raise exception.ItemNotFoundException(
                    "User not found: %s" % username)
            else:
                raise exception.CloudbaseInitException(
                    "Failed to get user info: %s" % ex.args[2])

    def set_user_password(self, username, password, password_expires=False):
        user_info = self._get_user_info(username, 1)
        user_info["password"] = password

        if password_expires:
            user_info["flags"] &= ~win32netcon.UF_DONT_EXPIRE_PASSWD
        else:
            user_info["flags"] |= win32netcon.UF_DONT_EXPIRE_PASSWD

        try:
            win32net.NetUserSetInfo(None, username, 1, user_info)
        except win32net.error as ex:
            raise exception.CloudbaseInitException(
                "Set user password failed: %s" % ex.args[2])

    def change_password_next_logon(self, username):
        """Force the given user to change the password at next logon."""
        user_info = self._get_user_info(username, 4)
        user_info["flags"] &= ~win32netcon.UF_DONT_EXPIRE_PASSWD
        user_info["password_expired"] = 1

        try:
            win32net.NetUserSetInfo(None, username, 4, user_info)
        except win32net.error as ex:
            raise exception.CloudbaseInitException(
                "Setting password expiration failed: %s" % ex.args[2])

    @staticmethod
    def _get_cch_referenced_domain_name(domain_name):
        return wintypes.DWORD(
            ctypes.sizeof(domain_name) // ctypes.sizeof(wintypes.WCHAR))

    def _get_user_sid_and_domain(self, username):
        sid = ctypes.create_string_buffer(1024)
        cbSid = wintypes.DWORD(ctypes.sizeof(sid))
        domainName = ctypes.create_unicode_buffer(1024)
        cchReferencedDomainName = self._get_cch_referenced_domain_name(
            domainName)
        sidNameUse = wintypes.DWORD()

        ret_val = advapi32.LookupAccountNameW(
            0, six.text_type(username), sid, ctypes.byref(cbSid), domainName,
            ctypes.byref(cchReferencedDomainName), ctypes.byref(sidNameUse))
        if not ret_val:
            raise exception.WindowsCloudbaseInitException(
                "Cannot get user SID: %r")

        return sid, domainName.value

    def add_user_to_local_group(self, username, groupname):

        lmi = Win32_LOCALGROUP_MEMBERS_INFO_3()
        lmi.lgrmi3_domainandname = six.text_type(username)

        ret_val = netapi32.NetLocalGroupAddMembers(0, six.text_type(groupname),
                                                   3, ctypes.addressof(lmi), 1)

        if ret_val == self.NERR_GroupNotFound:
            raise exception.CloudbaseInitException('Group not found')
        elif ret_val == self.ERROR_ACCESS_DENIED:
            raise exception.CloudbaseInitException('Access denied')
        elif ret_val == self.ERROR_NO_SUCH_MEMBER:
            raise exception.CloudbaseInitException('Username not found')
        elif ret_val == self.ERROR_MEMBER_IN_ALIAS:
            # The user is already a member of the group
            pass
        elif ret_val == self.ERROR_INVALID_MEMBER:
            raise exception.CloudbaseInitException('Invalid user')
        elif ret_val != 0:
            raise exception.CloudbaseInitException('Unknown error')

    def get_user_sid(self, username):
        try:
            user_info = self._get_user_info(username, 4)
            return str(user_info["user_sid"])[6:]
        except exception.ItemNotFoundException:
            # User not found
            pass

    def create_user_logon_session(self, username, password, domain='.',
                                  load_profile=True):
        token = wintypes.HANDLE()
        ret_val = advapi32.LogonUserW(six.text_type(username),
                                      six.text_type(domain),
                                      six.text_type(password), 2, 0,
                                      ctypes.byref(token))
        if not ret_val:
            raise exception.WindowsCloudbaseInitException(
                "User logon failed: %r")

        if load_profile:
            pi = Win32_PROFILEINFO()
            pi.dwSize = ctypes.sizeof(Win32_PROFILEINFO)
            pi.lpUserName = six.text_type(username)
            ret_val = userenv.LoadUserProfileW(token, ctypes.byref(pi))
            if not ret_val:
                kernel32.CloseHandle(token)
                raise exception.WindowsCloudbaseInitException(
                    "Cannot load user profile: %r")

        return token

    def close_user_logon_session(self, token):
        kernel32.CloseHandle(token)

    def get_user_home(self, username):
        user_sid = self.get_user_sid(username)
        if user_sid:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\'
                                'Microsoft\\Windows NT\\CurrentVersion\\'
                                'ProfileList\\%s' % user_sid) as key:
                return winreg.QueryValueEx(key, 'ProfileImagePath')[0]
        LOG.debug('Home directory not found for user %r', username)
        return None

    def sanitize_shell_input(self, value):
        return value.replace('"', '\\"')

    def set_host_name(self, new_host_name):
        ret_val = kernel32.SetComputerNameExW(
            self.ComputerNamePhysicalDnsHostname,
            six.text_type(new_host_name))
        if not ret_val:
            raise exception.WindowsCloudbaseInitException(
                "Cannot set host name: %r")
        return True

    def get_network_adapters(self):
        """Return available adapters as a list of tuples of (name, mac)."""
        conn = wmi.WMI(moniker='//./root/cimv2')
        # Get Ethernet adapters only
        wql = ('SELECT * FROM Win32_NetworkAdapter WHERE '
               'AdapterTypeId = 0 AND MACAddress IS NOT NULL')

        if self.check_os_version(6, 0):
            wql += ' AND PhysicalAdapter = True'

        q = conn.query(wql)
        return [(r.Name, r.MACAddress) for r in q]

    def get_dhcp_hosts_in_use(self):
        dhcp_hosts = []
        for net_addr in network.get_adapter_addresses():
            if net_addr["dhcp_enabled"] and net_addr["dhcp_server"]:
                dhcp_hosts.append((net_addr["mac_address"],
                                   net_addr["dhcp_server"]))
        return dhcp_hosts

    def set_ntp_client_config(self, ntp_hosts):
        base_dir = self._get_system_dir()
        w32tm_path = os.path.join(base_dir, "w32tm.exe")

        # Convert the NTP hosts list to a string, in order to pass
        # it to w32tm.
        ntp_hosts = ",".join(ntp_hosts)

        args = [w32tm_path, '/config', '/manualpeerlist:%s' % ntp_hosts,
                '/syncfromflags:manual', '/update']

        (out, err, ret_val) = self.execute_process(args, shell=False)
        if ret_val:
            raise exception.CloudbaseInitException(
                'w32tm failed to configure NTP.\nOutput: %(out)s\nError:'
                ' %(err)s' % {'out': out, 'err': err})

    def set_network_adapter_mtu(self, mac_address, mtu):
        if not self.check_os_version(6, 0):
            raise exception.CloudbaseInitException(
                'Setting the MTU is currently not supported on Windows XP '
                'and Windows Server 2003')

        iface_index_list = [
            net_addr["interface_index"] for net_addr
            in network.get_adapter_addresses()
            if net_addr["mac_address"] == mac_address]

        if not iface_index_list:
            raise exception.CloudbaseInitException(
                'Network interface with MAC address "%s" not found' %
                mac_address)
        else:
            iface_index = iface_index_list[0]

            LOG.debug('Setting MTU for interface "%(mac_address)s" with '
                      'value "%(mtu)s"',
                      {'mac_address': mac_address, 'mtu': mtu})

            base_dir = self._get_system_dir()
            netsh_path = os.path.join(base_dir, 'netsh.exe')

            args = [netsh_path, "interface", "ipv4", "set", "subinterface",
                    str(iface_index), "mtu=%s" % mtu,
                    "store=persistent"]
            (out, err, ret_val) = self.execute_process(args, shell=False)
            if ret_val:
                raise exception.CloudbaseInitException(
                    'Setting MTU for interface "%(mac_address)s" with '
                    'value "%(mtu)s" failed' % {'mac_address': mac_address,
                                                'mtu': mtu})

    def set_static_network_config(self, mac_address, address, netmask,
                                  broadcast, gateway, dnsnameservers):
        conn = wmi.WMI(moniker='//./root/cimv2')

        query = conn.query("SELECT * FROM Win32_NetworkAdapter WHERE "
                           "MACAddress = '{}'".format(mac_address))
        if not len(query):
            raise exception.CloudbaseInitException(
                "Network adapter not found")

        adapter_config = query[0].associators(
            wmi_result_class='Win32_NetworkAdapterConfiguration')[0]

        LOG.debug("Setting static IP address")
        (ret_val,) = adapter_config.EnableStatic([address], [netmask])
        if ret_val > 1:
            raise exception.CloudbaseInitException(
                "Cannot set static IP address on network adapter (%d)",
                ret_val)
        reboot_required = (ret_val == 1)

        if gateway:
            LOG.debug("Setting static gateways")
            (ret_val,) = adapter_config.SetGateways([gateway], [1])
            if ret_val > 1:
                raise exception.CloudbaseInitException(
                    "Cannot set gateway on network adapter (%d)",
                    ret_val)
            reboot_required = reboot_required or ret_val == 1

        if dnsnameservers:
            LOG.debug("Setting static DNS servers")
            (ret_val,) = adapter_config.SetDNSServerSearchOrder(dnsnameservers)
            if ret_val > 1:
                raise exception.CloudbaseInitException(
                    "Cannot set DNS on network adapter (%d)",
                    ret_val)
            reboot_required = reboot_required or ret_val == 1

        return reboot_required

    def set_static_network_config_v6(self, mac_address, address6,
                                     netmask6, gateway6):
        """Set IPv6 info for a network card."""

        # Get local properties by MAC identification.
        adapters = network.get_adapter_addresses()
        for adapter in adapters:
            if mac_address == adapter["mac_address"]:
                ifname = adapter["friendly_name"]
                ifindex = adapter["interface_index"]
                break
        else:
            raise exception.CloudbaseInitException(
                "Adapter with MAC {!r} not available".format(mac_address))

        # TODO(cpoieana): Extend support for other platforms.
        #                 Currently windows8 @ ws2012 or above.
        if not self.check_os_version(6, 2):
            LOG.warning("Setting IPv6 info not available "
                        "on this system")
            return
        conn = wmi.WMI(moniker='//./root/StandardCimv2')
        query = conn.query("SELECT * FROM MSFT_NetIPAddress "
                           "WHERE InterfaceAlias = '{}'".format(ifname))
        netip = query[0]

        params = {
            "InterfaceIndex": ifindex,
            "InterfaceAlias": ifname,
            "IPAddress": address6,
            "AddressFamily": AF_INET6,
            "PrefixLength": netmask6,
            # Manual set type.
            "Type": UNICAST,
            "PrefixOrigin": MANUAL,
            "SuffixOrigin": MANUAL,
            "AddressState": PREFERRED_ADDR,
            # No expiry.
            "ValidLifetime": None,
            "PreferredLifetime": None,
            "SkipAsSource": False,
            "DefaultGateway": gateway6,
            "PolicyStore": None,
            "PassThru": False,
        }
        LOG.debug("Setting IPv6 info for %s", ifname)
        try:
            netip.Create(**params)
        except wmi.x_wmi as exc:
            raise exception.CloudbaseInitException(exc.com_error)

    def _get_config_key_name(self, section):
        key_name = self._config_key
        if section:
            key_name += section.replace('/', '\\') + '\\'
        return key_name

    def set_config_value(self, name, value, section=None):
        key_name = self._get_config_key_name(section)

        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                              key_name) as key:
            if type(value) == int:
                regtype = winreg.REG_DWORD
            else:
                regtype = winreg.REG_SZ
            winreg.SetValueEx(key, name, 0, regtype, value)

    def get_config_value(self, name, section=None):
        key_name = self._get_config_key_name(section)

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                key_name) as key:
                (value, regtype) = winreg.QueryValueEx(key, name)
                return value
        except WindowsError:
            return None

    def wait_for_boot_completion(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                "SYSTEM\\Setup\\Status\\SysprepStatus", 0,
                                winreg.KEY_READ) as key:
                while True:
                    gen_state = winreg.QueryValueEx(key,
                                                    "GeneralizationState")[0]
                    if gen_state == 7:
                        break
                    time.sleep(1)
                    LOG.info('Waiting for sysprep completion. '
                             'GeneralizationState: %d', gen_state)
        except WindowsError as ex:
            if ex.winerror == 2:
                LOG.debug('Sysprep data not found in the registry, '
                          'skipping sysprep completion check.')
            else:
                raise ex

    def _get_service(self, service_name):
        conn = wmi.WMI(moniker='//./root/cimv2')
        service_list = conn.Win32_Service(Name=service_name)
        if len(service_list):
            return service_list[0]

    def check_service_exists(self, service_name):
        try:
            with self._get_service_handle(service_name):
                return True
        except pywintypes.error as ex:
            print(ex)
            if ex.winerror == winerror.ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise

    def get_service_status(self, service_name):
        service = self._get_service(service_name)
        return service.State

    def get_service_start_mode(self, service_name):
        service = self._get_service(service_name)
        return service.StartMode

    def set_service_start_mode(self, service_name, start_mode):
        # TODO(alexpilotti): Handle the "Delayed Start" case
        service = self._get_service(service_name)
        (ret_val,) = service.ChangeStartMode(start_mode)
        if ret_val != 0:
            raise exception.CloudbaseInitException(
                'Setting service %(service_name)s start mode failed with '
                'return value: %(ret_val)d' % {'service_name': service_name,
                                               'ret_val': ret_val})

    def start_service(self, service_name):
        LOG.debug('Starting service %s', service_name)
        service = self._get_service(service_name)
        (ret_val,) = service.StartService()
        if ret_val != 0:
            raise exception.CloudbaseInitException(
                'Starting service %(service_name)s failed with return value: '
                '%(ret_val)d' % {'service_name': service_name,
                                 'ret_val': ret_val})

    def stop_service(self, service_name):
        LOG.debug('Stopping service %s', service_name)
        service = self._get_service(service_name)
        (ret_val,) = service.StopService()
        if ret_val != 0:
            raise exception.CloudbaseInitException(
                'Stopping service %(service_name)s failed with return value:'
                ' %(ret_val)d' % {'service_name': service_name,
                                  'ret_val': ret_val})

    @staticmethod
    @contextlib.contextmanager
    def _get_service_handle(service_name,
                            service_access=win32service.SERVICE_QUERY_CONFIG,
                            scm_access=win32service.SC_MANAGER_CONNECT):
        hscm = win32service.OpenSCManager(None, None, scm_access)
        hs = None
        try:
            hs = win32service.OpenService(hscm, service_name, service_access)
            yield hs
        finally:
            if hs:
                win32service.CloseServiceHandle(hs)
            win32service.CloseServiceHandle(hscm)

    def set_service_credentials(self, service_name, username, password):
        LOG.debug('Setting service credentials: %s', service_name)
        with self._get_service_handle(
                service_name, win32service.SERVICE_CHANGE_CONFIG) as hs:
            win32service.ChangeServiceConfig(
                hs,
                win32service.SERVICE_NO_CHANGE,
                win32service.SERVICE_NO_CHANGE,
                win32service.SERVICE_NO_CHANGE,
                None,
                None,
                False,
                None,
                username,
                password,
                None)

    def get_service_username(self, service_name):
        LOG.debug('Getting service username: %s', service_name)
        with self._get_service_handle(service_name) as hs:
            cfg = win32service.QueryServiceConfig(hs)
            return cfg[7]

    def reset_service_password(self):
        """This is needed to avoid pass the hash attacks."""
        if not self.check_service_exists(self._service_name):
            LOG.info("Service does not exist: %s", self._service_name)
            return False

        service_username = self.get_service_username(self._service_name)
        # Ignore builtin accounts
        if "\\" not in service_username:
            LOG.info("Skipping password reset, service running as a built-in "
                     "account: %s", service_username)
            return False
        domain, username = service_username.split('\\')
        if domain != ".":
            LOG.info("Skipping password reset, service running as a domain "
                     "account: %s", service_username)
            return False

        LOG.debug('Resetting password for service user: %s', service_username)
        maximum_length = self.get_maximum_password_length()
        password = self.generate_random_password(maximum_length)
        self.set_user_password(username, password)
        self.set_service_credentials(
            self._service_name, service_username, password)
        return True

    def terminate(self):
        # Wait for the service to start. Polling the service "Started" property
        # is not enough
        time.sleep(3)
        self.stop_service(self._service_name)

    def get_default_gateway(self):
        default_routes = [r for r in self._get_ipv4_routing_table()
                          if r[0] == '0.0.0.0']
        if default_routes:
            return default_routes[0][3], default_routes[0][2]
        else:
            return None, None

    @staticmethod
    def _heap_alloc(heap, size):
        table_mem = kernel32.HeapAlloc(heap, 0, ctypes.c_size_t(size.value))
        if not table_mem:
            raise exception.CloudbaseInitException(
                'Unable to allocate memory for the IP forward table')
        return table_mem

    @contextlib.contextmanager
    def _get_forward_table(self):
        heap = kernel32.GetProcessHeap()
        forward_table_size = ctypes.sizeof(Win32_MIB_IPFORWARDTABLE)
        size = wintypes.ULONG(forward_table_size)
        table_mem = self._heap_alloc(heap, size)

        p_forward_table = ctypes.cast(
            table_mem, ctypes.POINTER(Win32_MIB_IPFORWARDTABLE))

        try:
            err = iphlpapi.GetIpForwardTable(p_forward_table,
                                             ctypes.byref(size), 0)
            if err == self.ERROR_INSUFFICIENT_BUFFER:
                kernel32.HeapFree(heap, 0, p_forward_table)
                table_mem = self._heap_alloc(heap, size)
                p_forward_table = ctypes.cast(
                    table_mem,
                    ctypes.POINTER(Win32_MIB_IPFORWARDTABLE))
                err = iphlpapi.GetIpForwardTable(p_forward_table,
                                                 ctypes.byref(size), 0)

            if err and err != kernel32.ERROR_NO_DATA:
                raise exception.CloudbaseInitException(
                    'Unable to get IP forward table. Error: %s' % err)

            yield p_forward_table
        finally:
            kernel32.HeapFree(heap, 0, p_forward_table)

    def _get_ipv4_routing_table(self):
        routing_table = []
        with self._get_forward_table() as p_forward_table:
            forward_table = p_forward_table.contents
            table = ctypes.cast(
                ctypes.addressof(forward_table.table),
                ctypes.POINTER(Win32_MIB_IPFORWARDROW *
                               forward_table.dwNumEntries)).contents

            for row in table:
                destination = Ws2_32.inet_ntoa(
                    row.dwForwardDest).decode()
                netmask = Ws2_32.inet_ntoa(
                    row.dwForwardMask).decode()
                gateway = Ws2_32.inet_ntoa(
                    row.dwForwardNextHop).decode()
                routing_table.append((
                    destination,
                    netmask,
                    gateway,
                    row.dwForwardIfIndex,
                    row.dwForwardMetric1))

        return routing_table

    def check_static_route_exists(self, destination):
        return len([r for r in self._get_ipv4_routing_table()
                    if r[0] == destination]) > 0

    def add_static_route(self, destination, mask, next_hop, interface_index,
                         metric):
        args = ['ROUTE', 'ADD', destination, 'MASK', mask, next_hop]
        (out, err, ret_val) = self.execute_process(args)
        # Cannot use the return value to determine the outcome
        if ret_val or err:
            raise exception.CloudbaseInitException(
                'Unable to add route: %s' % err)

    def check_os_version(self, major, minor, build=0):
        vi = Win32_OSVERSIONINFOEX_W()
        vi.dwOSVersionInfoSize = ctypes.sizeof(Win32_OSVERSIONINFOEX_W)

        vi.dwMajorVersion = major
        vi.dwMinorVersion = minor
        vi.dwBuildNumber = build

        mask = 0
        for type_mask in [VER_MAJORVERSION, VER_MINORVERSION, VER_BUILDNUMBER]:
            mask = kernel32.VerSetConditionMask(mask, type_mask,
                                                VER_GREATER_EQUAL)

        type_mask = VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER
        ret_val = ntdll.RtlVerifyVersionInfo(ctypes.byref(vi), type_mask, mask)
        if not ret_val:
            return True
        elif ret_val == self.STATUS_REVISION_MISMATCH:
            return False
        else:
            raise exception.CloudbaseInitException(
                "RtlVerifyVersionInfo failed with error: %s" % ret_val)

    def get_volume_label(self, drive):
        max_label_size = 261
        label = ctypes.create_unicode_buffer(max_label_size)
        ret_val = kernel32.GetVolumeInformationW(six.text_type(drive), label,
                                                 max_label_size, 0, 0, 0, 0, 0)
        if ret_val:
            return label.value

    def generate_random_password(self, length):
        while True:
            pwd = super(WindowsUtils, self).generate_random_password(length)
            # Make sure that the Windows complexity requirements are met:
            # http://technet.microsoft.com/en-us/library/cc786468(v=ws.10).aspx
            valid = True
            for r in ["[a-z]", "[A-Z]", "[0-9]"]:
                if not re.search(r, pwd):
                    valid = False
            if valid:
                return pwd

    def _split_str_buf_list(self, buf, buf_len):
        i = 0
        value = ''
        values = []
        while i < buf_len:
            c = buf[i]
            if c != '\x00':
                value += c
            else:
                values.append(value)
                value = ''
            i += 1

        return values

    def _get_logical_drives(self):
        buf_size = self.MAX_PATH
        buf = ctypes.create_unicode_buffer(buf_size + 1)
        buf_len = kernel32.GetLogicalDriveStringsW(buf_size, buf)
        if not buf_len:
            raise exception.WindowsCloudbaseInitException(
                "GetLogicalDriveStringsW failed: %r")

        return self._split_str_buf_list(buf, buf_len)

    def get_cdrom_drives(self):
        drives = self._get_logical_drives()
        return [d for d in drives if kernel32.GetDriveTypeW(d) ==
                self.DRIVE_CDROM]

    def _is_64bit_arch(self):
        # interpreter's bits
        return struct.calcsize("P") == 8

    def get_physical_disks(self):
        physical_disks = []

        disk_guid = GUID_DEVINTERFACE_DISK
        handle_disks = setupapi.SetupDiGetClassDevsW(
            ctypes.byref(disk_guid), None, None,
            self.DIGCF_PRESENT | self.DIGCF_DEVICEINTERFACE)
        if handle_disks == self.INVALID_HANDLE_VALUE:
            raise exception.CloudbaseInitException(
                "SetupDiGetClassDevs failed")

        try:
            did = Win32_SP_DEVICE_INTERFACE_DATA()
            did.cbSize = ctypes.sizeof(Win32_SP_DEVICE_INTERFACE_DATA)

            index = 0
            while setupapi.SetupDiEnumDeviceInterfaces(
                    handle_disks, None, ctypes.byref(disk_guid), index,
                    ctypes.byref(did)):
                index += 1
                handle_disk = self.INVALID_HANDLE_VALUE

                required_size = wintypes.DWORD()
                if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                        handle_disks, ctypes.byref(did), None, 0,
                        ctypes.byref(required_size), None):
                    if (kernel32.GetLastError() !=
                            self.ERROR_INSUFFICIENT_BUFFER):
                        raise exception.WindowsCloudbaseInitException(
                            "SetupDiGetDeviceInterfaceDetailW failed: %r")

                pdidd = ctypes.cast(
                    msvcrt.malloc(ctypes.c_size_t(required_size.value)),
                    ctypes.POINTER(Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W))

                try:
                    pdidd.contents.cbSize = ctypes.sizeof(
                        Win32_SP_DEVICE_INTERFACE_DETAIL_DATA_W)
                    if not self._is_64bit_arch():
                        # NOTE(cpoieana): For some reason, on x86 platforms
                        # the alignment or content of the struct
                        # is not taken into consideration.
                        pdidd.contents.cbSize = 6

                    if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                            handle_disks, ctypes.byref(did), pdidd,
                            required_size, None, None):
                        raise exception.WindowsCloudbaseInitException(
                            "SetupDiGetDeviceInterfaceDetailW failed: %r")

                    device_path = ctypes.cast(
                        pdidd.contents.DevicePath, wintypes.LPWSTR).value

                    handle_disk = kernel32.CreateFileW(
                        device_path, 0, self.FILE_SHARE_READ,
                        None, self.OPEN_EXISTING, 0, 0)
                    if handle_disk == self.INVALID_HANDLE_VALUE:
                        raise exception.CloudbaseInitException(
                            'CreateFileW failed')

                    sdn = Win32_STORAGE_DEVICE_NUMBER()

                    b = wintypes.DWORD()
                    if not kernel32.DeviceIoControl(
                            handle_disk, self.IOCTL_STORAGE_GET_DEVICE_NUMBER,
                            None, 0, ctypes.byref(sdn), ctypes.sizeof(sdn),
                            ctypes.byref(b), None):
                        raise exception.WindowsCloudbaseInitException(
                            'DeviceIoControl failed: %r')

                    physical_disks.append(
                        r"\\.\PHYSICALDRIVE%d" % sdn.DeviceNumber)
                finally:
                    msvcrt.free(pdidd)
                    if handle_disk != self.INVALID_HANDLE_VALUE:
                        kernel32.CloseHandle(handle_disk)
        finally:
            setupapi.SetupDiDestroyDeviceInfoList(handle_disks)

        return physical_disks

    def get_volumes(self):
        """Retrieve a list with all the volumes found on all disks."""
        volumes = []
        volume = ctypes.create_unicode_buffer(chr(0) * self.MAX_PATH)

        handle_volumes = kernel32.FindFirstVolumeW(volume, self.MAX_PATH)
        if handle_volumes == self.INVALID_HANDLE_VALUE:
            raise exception.WindowsCloudbaseInitException(
                "FindFirstVolumeW failed: %r")

        try:
            while True:
                volumes.append(volume.value)
                found = kernel32.FindNextVolumeW(handle_volumes, volume,
                                                 self.MAX_PATH)
                if not found:
                    errno = ctypes.GetLastError()
                    if errno == self.ERROR_NO_MORE_FILES:
                        break
                    else:
                        raise exception.WindowsCloudbaseInitException(
                            "FindNextVolumeW failed: %r")
        finally:
            kernel32.FindVolumeClose(handle_volumes)

        return volumes

    def _get_fw_protocol(self, protocol):
        if protocol == self.PROTOCOL_TCP:
            fw_protocol = self._FW_IP_PROTOCOL_TCP
        elif protocol == self.PROTOCOL_UDP:
            fw_protocol = self._FW_IP_PROTOCOL_UDP
        else:
            raise NotImplementedError("Unsupported protocol")
        return fw_protocol

    def firewall_create_rule(self, name, port, protocol, allow=True):
        if not allow:
            raise NotImplementedError()

        fw_port = client.Dispatch("HNetCfg.FWOpenPort")
        fw_port.Name = name
        fw_port.Protocol = self._get_fw_protocol(protocol)
        fw_port.Port = port
        fw_port.Scope = self._FW_SCOPE_ALL
        fw_port.Enabled = True

        fw_mgr = client.Dispatch("HNetCfg.FwMgr")
        fw_profile = fw_mgr.LocalPolicy.CurrentProfile
        fw_profile = fw_profile.GloballyOpenPorts.Add(fw_port)

    def firewall_remove_rule(self, name, port, protocol, allow=True):
        if not allow:
            raise NotImplementedError()

        fw_mgr = client.Dispatch("HNetCfg.FwMgr")
        fw_profile = fw_mgr.LocalPolicy.CurrentProfile

        fw_protocol = self._get_fw_protocol(protocol)
        fw_profile = fw_profile.GloballyOpenPorts.Remove(port, fw_protocol)

    def is_wow64(self):
        return win32process.IsWow64Process()

    def get_system32_dir(self):
        return os.path.expandvars('%windir%\\system32')

    def get_syswow64_dir(self):
        return os.path.expandvars('%windir%\\syswow64')

    def get_sysnative_dir(self):
        return os.path.expandvars('%windir%\\sysnative')

    def check_sysnative_dir_exists(self):
        sysnative_dir_exists = os.path.isdir(self.get_sysnative_dir())
        if not sysnative_dir_exists and self.is_wow64():
            LOG.warning('Unable to validate sysnative folder presence. '
                        'If Target OS is Server 2003 x64, please ensure '
                        'you have KB942589 installed')
        return sysnative_dir_exists

    def _get_system_dir(self, sysnative=True):
        """Return Windows system directory with compatibility support.

        Depending on the interpreter bits and platform architecture,
        the return value may vary between
        C:\Windows\(System32|SysWOW64|Sysnative).
        Note that "Sysnative" is just an alias (doesn't really exist on disk).

        More info about this can be found in documentation.
        """
        if sysnative and self.check_sysnative_dir_exists():
            return self.get_sysnative_dir()
        if not sysnative and self._is_64bit_arch():
            return self.get_syswow64_dir()
        return self.get_system32_dir()

    def is_nano_server(self):
        return self._check_server_level("NanoServer")

    def _check_server_level(self, server_level):
        try:
            with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Server\\"
                    "ServerLevels") as key:
                return winreg.QueryValueEx(key, server_level)[0] == 1
        except WindowsError as ex:
            if ex.winerror == 2:
                return False
            else:
                raise

    def execute_powershell_script(self, script_path, sysnative=True):
        base_dir = self._get_system_dir(sysnative)
        powershell_path = os.path.join(base_dir,
                                       'WindowsPowerShell\\v1.0\\'
                                       'powershell.exe')

        args = [powershell_path]
        if not self.is_nano_server():
            args += ['-ExecutionPolicy', 'RemoteSigned', '-NonInteractive',
                     '-File']
        args.append(script_path)

        return self.execute_process(args, shell=False)

    def execute_system32_process(self, args, shell=True, decode_output=False,
                                 sysnative=True):
        base_dir = self._get_system_dir(sysnative)
        process_path = os.path.join(base_dir, args[0])
        return self.execute_process([process_path] + args[1:],
                                    decode_output=decode_output, shell=shell)

    def get_maximum_password_length(self):
        return 20

    def set_timezone(self, timezone_name):
        windows_name = windows_tz.tz_win.get(timezone_name)
        if not windows_name:
            raise exception.CloudbaseInitException(
                "The given timezone name is unrecognised: %r" % timezone_name)
        timezone.Timezone(windows_name).set(self)
