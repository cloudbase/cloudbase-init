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
import subprocess
import time

import netaddr
from oslo_log import log as oslo_logging
import pywintypes
import six
from six.moves import winreg
from tzlocal import windows_tz
import win32api
from win32com import client
import win32net
import win32netcon
import win32process
import win32security
import win32service
import winerror

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.osutils import base
from cloudbaseinit.utils import classloader
from cloudbaseinit.utils import retry_decorator
from cloudbaseinit.utils.windows import disk
from cloudbaseinit.utils.windows import network
from cloudbaseinit.utils.windows import privilege
from cloudbaseinit.utils.windows import timezone
from cloudbaseinit.utils.windows import wmi_loader

wmi = wmi_loader.wmi()

LOG = oslo_logging.getLogger(__name__)

AF_INET = 2
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
secur32 = ctypes.windll.secur32


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


class Win32_STARTUPINFO_W(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.POINTER(wintypes.BYTE)),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]


class Win32_PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD),
    ]


advapi32.CreateProcessAsUserW.argtypes = [wintypes.HANDLE,
                                          wintypes.LPCWSTR,
                                          wintypes.LPWSTR,
                                          ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          wintypes.BOOL,
                                          wintypes.DWORD,
                                          ctypes.c_void_p,
                                          wintypes.LPCWSTR,
                                          ctypes.POINTER(
                                              Win32_STARTUPINFO_W),
                                          ctypes.POINTER(
                                              Win32_PROCESS_INFORMATION)]
advapi32.CreateProcessAsUserW.restype = wintypes.BOOL

msvcrt.malloc.argtypes = [ctypes.c_size_t]
msvcrt.malloc.restype = ctypes.c_void_p

msvcrt.free.argtypes = [ctypes.c_void_p]
msvcrt.free.restype = None

ntdll.RtlGetVersion.argtypes = [
    ctypes.POINTER(Win32_OSVERSIONINFOEX_W)]
ntdll.RtlGetVersion.restype = wintypes.DWORD

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

kernel32.GetVolumeNameForVolumeMountPointW.argtypes = [wintypes.LPCWSTR,
                                                       wintypes.LPWSTR,
                                                       wintypes.DWORD]
kernel32.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL

kernel32.GetVolumePathNamesForVolumeNameW.argtypes = [wintypes.LPCWSTR,
                                                      wintypes.LPWSTR,
                                                      wintypes.DWORD,
                                                      ctypes.POINTER(
                                                          wintypes.DWORD)]
kernel32.GetVolumePathNamesForVolumeNameW.restype = wintypes.BOOL

kernel32.FindFirstVolumeW.argtypes = [wintypes.LPWSTR, wintypes.DWORD]
kernel32.FindFirstVolumeW.restype = wintypes.HANDLE

kernel32.FindNextVolumeW.argtypes = [wintypes.HANDLE,
                                     wintypes.LPWSTR,
                                     wintypes.DWORD]
kernel32.FindNextVolumeW.restype = wintypes.BOOL

kernel32.FindVolumeClose.argtypes = [wintypes.HANDLE]
kernel32.FindVolumeClose.restype = wintypes.BOOL

iphlpapi.GetIpForwardTable.argtypes = [
    ctypes.POINTER(Win32_MIB_IPFORWARDTABLE),
    ctypes.POINTER(wintypes.ULONG),
    wintypes.BOOL]
iphlpapi.GetIpForwardTable.restype = wintypes.DWORD

Ws2_32.inet_ntoa.restype = ctypes.c_char_p

secur32.GetUserNameExW.argtypes = [wintypes.DWORD,
                                   wintypes.LPWSTR,
                                   ctypes.POINTER(wintypes.ULONG)]
secur32.GetUserNameExW.restype = wintypes.BOOL

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
    ERROR_PATH_NOT_FOUND = 3
    ERROR_ACCESS_DENIED = 5
    ERROR_INSUFFICIENT_BUFFER = 122
    ERROR_INVALID_NAME = 123
    ERROR_NO_DATA = 232
    ERROR_MORE_DATA = 234
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

    INFINITE = 0xFFFFFFFF

    CREATE_NEW_CONSOLE = 0x10

    LOGON32_LOGON_BATCH = 4
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_LOGON_SERVICE = 5

    LOGON32_PROVIDER_DEFAULT = 0

    EXTENDED_NAME_FORMAT_SAM_COMPATIBLE = 2

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

    _SERVICE_START_TYPE_MAP = {
        SERVICE_START_MODE_AUTOMATIC:
        win32service.SERVICE_AUTO_START,
        SERVICE_START_MODE_MANUAL:
        win32service.SERVICE_DEMAND_START,
        SERVICE_START_MODE_DISABLED:
        win32service.SERVICE_DISABLED}

    _SERVICE_STATUS_MAP = {
        win32service.SERVICE_CONTINUE_PENDING:
        SERVICE_STATUS_CONTINUE_PENDING,
        win32service.SERVICE_PAUSE_PENDING:
        SERVICE_STATUS_PAUSE_PENDING,
        win32service.SERVICE_PAUSED:
        SERVICE_STATUS_PAUSED,
        win32service.SERVICE_RUNNING:
        SERVICE_STATUS_RUNNING,
        win32service.SERVICE_START_PENDING:
        SERVICE_STATUS_START_PENDING,
        win32service.SERVICE_STOP_PENDING:
        SERVICE_STATUS_STOP_PENDING,
        win32service.SERVICE_STOPPED:
        SERVICE_STATUS_STOPPED,
    }

    ComputerNamePhysicalDnsHostname = 5

    _config_key = 'SOFTWARE\\Cloudbase Solutions\\Cloudbase-Init\\'
    _service_name = 'cloudbase-init'

    _FW_IP_PROTOCOL_TCP = 6
    _FW_IP_PROTOCOL_UDP = 17
    _FW_SCOPE_ALL = 0
    _FW_SCOPE_LOCAL_SUBNET = 1

    VER_NT_WORKSTATION = 1

    def __init__(self):
        self._network_team_manager = None

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

    def rename_user(self, username, new_username):
        user_info = {
            "name": new_username,
        }
        try:
            win32net.NetUserSetInfo(None, username, 0, user_info)
        except win32net.error as ex:
            if ex.args[0] == self.NERR_UserNotFound:
                raise exception.ItemNotFoundException(
                    "User not found: %s" % username)
            else:
                raise exception.CloudbaseInitException(
                    "Renaming user failed: %s" % ex.args[2])

    def set_user_info(self, username, full_name=None,
                      disabled=False, expire_interval=None):

        user_info = self._get_user_info(username, 2)

        if full_name:
            user_info["full_name"] = full_name

        if disabled:
            user_info["flags"] |= win32netcon.UF_ACCOUNTDISABLE
        else:
            user_info["flags"] &= ~win32netcon.UF_ACCOUNTDISABLE

        if expire_interval is not None:
            user_info["acct_expires"] = int(expire_interval)
        else:
            user_info["acct_expires"] = win32netcon.TIMEQ_FOREVER

        try:
            win32net.NetUserSetInfo(None, username, 2, user_info)
        except win32net.error as ex:
            if ex.args[0] == self.NERR_UserNotFound:
                raise exception.ItemNotFoundException(
                    "User not found: %s" % username)
            else:
                LOG.debug(ex)
                raise exception.CloudbaseInitException(
                    "Setting user info failed: %s" % ex.args[2])

    def enum_users(self):
        usernames = []
        resume_handle = 0
        while True:
            try:
                users_info, total, resume_handle = win32net.NetUserEnum(
                    None, 0, win32netcon.FILTER_NORMAL_ACCOUNT, resume_handle)
            except win32net.error as ex:
                raise exception.CloudbaseInitException(
                    "Enumerating users failed: %s" % ex.args[2])

            usernames += [u["name"] for u in users_info]
            if not resume_handle:
                return usernames

    def is_builtin_admin(self, username):
        sid = self.get_user_sid(username)
        return sid and sid.startswith(u"S-1-5-") and sid.endswith(u"-500")

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

    def group_exists(self, group):
        try:
            self._get_group_info(group, 1)
            return True
        except exception.ItemNotFoundException:
            # Group not found
            return False

    def _get_group_info(self, group, level):
        try:
            return win32net.NetLocalGroupGetInfo(None, group, level)
        except win32net.error as ex:
            if ex.args[0] == self.NERR_GroupNotFound:
                raise exception.ItemNotFoundException(
                    "Group not found: %s" % group)
            else:
                raise exception.CloudbaseInitException(
                    "Failed to get group info: %s" % ex.args[2])

    def create_group(self, group, description=None):
        group_info = {"name": group}

        try:
            win32net.NetLocalGroupAdd(None, 0, group_info)
        except win32net.error as ex:
            raise exception.CloudbaseInitException(
                "Create group failed: %s" % ex.args[2])

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
                                                   3, ctypes.pointer(lmi), 1)

        if ret_val == self.NERR_GroupNotFound:
            raise exception.CloudbaseInitException("Group '%s' not found"
                                                   % groupname)
        elif ret_val == self.ERROR_ACCESS_DENIED:
            raise exception.CloudbaseInitException('Access denied')
        elif ret_val == self.ERROR_NO_SUCH_MEMBER:
            raise exception.CloudbaseInitException("Username '%s' not found"
                                                   % username)
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
                                  load_profile=True,
                                  logon_type=LOGON32_LOGON_INTERACTIVE):
        LOG.debug("Creating logon session for user: %(domain)s\\%(username)s",
                  {"username": username, "domain": domain})

        token = wintypes.HANDLE()
        ret_val = advapi32.LogonUserW(six.text_type(username),
                                      six.text_type(domain),
                                      six.text_type(password),
                                      logon_type,
                                      self.LOGON32_PROVIDER_DEFAULT,
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

    def get_current_user(self):
        """Get the user account name from the underlying instance."""
        buf_len = wintypes.ULONG(512)
        buf = ctypes.create_unicode_buffer(512)

        ret_val = secur32.GetUserNameExW(
            self.EXTENDED_NAME_FORMAT_SAM_COMPATIBLE,
            buf, ctypes.byref(buf_len))
        if not ret_val:
            raise exception.WindowsCloudbaseInitException(
                "GetUserNameExW failed: %r")

        return buf.value.split("\\")

    def execute_process_as_user(self, token, args, wait=True,
                                new_console=False):
        """Executes processes as an user.

        :param token: Represents the user logon session token, resulted from
                      running the 'create_user_logon_session' method.
        :param args: The arguments with which the process will be run with.
        :param wait: Specifies if it's needed to wait for the process
                     handler to finish up running all the operations
                     on the process object.
        :param new_console: Specifies whether the process should run
                            under a new console or not.
        :return: The exit code value resulted from the running process.
        :rtype: int
        """
        LOG.debug("Executing process as user, command line: %s", args)

        proc_info = Win32_PROCESS_INFORMATION()
        startup_info = Win32_STARTUPINFO_W()
        startup_info.cb = ctypes.sizeof(Win32_STARTUPINFO_W)
        startup_info.lpDesktop = ""

        flags = self.CREATE_NEW_CONSOLE if new_console else 0
        cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(args))

        try:
            ret_val = advapi32.CreateProcessAsUserW(
                token, None, cmdline, None, None, False, flags, None, None,
                ctypes.byref(startup_info), ctypes.byref(proc_info))
            if not ret_val:
                raise exception.WindowsCloudbaseInitException(
                    "CreateProcessAsUserW failed: %r")

            if wait and proc_info.hProcess:
                kernel32.WaitForSingleObject(
                    proc_info.hProcess, self.INFINITE)

                exit_code = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(
                        proc_info.hProcess, ctypes.byref(exit_code)):
                    raise exception.WindowsCloudbaseInitException(
                        "GetExitCodeProcess failed: %r")

                return exit_code.value
        finally:
            if proc_info.hProcess:
                kernel32.CloseHandle(proc_info.hProcess)
            if proc_info.hThread:
                kernel32.CloseHandle(proc_info.hThread)

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
        return [(r.NetConnectionID, r.MACAddress) for r in q]

    def get_dhcp_hosts_in_use(self):
        dhcp_hosts = []
        for net_addr in network.get_adapter_addresses():
            if net_addr["dhcp_enabled"] and net_addr["dhcp_server"]:
                dhcp_hosts.append((net_addr["friendly_name"],
                                   net_addr["mac_address"],
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

    def get_network_adapter_name_by_mac_address(self, mac_address):
        iface_index_list = [
            net_addr for net_addr
            in network.get_adapter_addresses()
            if net_addr["mac_address"] is not None and
            net_addr["mac_address"].lower() == mac_address.lower()]

        if not iface_index_list:
            raise exception.ItemNotFoundException(
                'Network interface with MAC address "%s" not found' %
                mac_address)

        if len(iface_index_list) > 1:
            raise exception.CloudbaseInitException(
                'Multiple network interfaces with MAC address "%s" exist' %
                mac_address)

        return iface_index_list[0]["friendly_name"]

    @retry_decorator.retry_decorator(
        max_retry_count=3, exceptions=exception.ItemNotFoundException)
    def set_network_adapter_mtu(self, name, mtu):
        if not self.check_os_version(6, 0):
            raise exception.CloudbaseInitException(
                'Setting the MTU is currently not supported on Windows XP '
                'and Windows Server 2003')

        iface_index_list = [
            net_addr["interface_index"] for net_addr
            in network.get_adapter_addresses()
            if net_addr["friendly_name"] == name]

        if not iface_index_list:
            raise exception.ItemNotFoundException(
                'Network interface with name "%s" not found' %
                name)
        else:
            iface_index = iface_index_list[0]

            LOG.debug('Setting MTU for interface "%(name)s" with '
                      'value "%(mtu)s"',
                      {'name': name, 'mtu': mtu})

            base_dir = self._get_system_dir()
            netsh_path = os.path.join(base_dir, 'netsh.exe')

            args = [netsh_path, "interface", "ipv4", "set", "subinterface",
                    str(iface_index), "mtu=%s" % mtu,
                    "store=persistent"]
            (out, err, ret_val) = self.execute_process(args, shell=False)
            if ret_val:
                raise exception.CloudbaseInitException(
                    'Setting MTU for interface "%(name)s" with '
                    'value "%(mtu)s" failed' % {'name': name, 'mtu': mtu})

    def rename_network_adapter(self, old_name, new_name):
        base_dir = self._get_system_dir()
        netsh_path = os.path.join(base_dir, 'netsh.exe')

        args = [netsh_path, "interface", "set", "interface",
                'name=%s' % old_name, 'newname=%s' % new_name]
        (out, err, ret_val) = self.execute_process(args, shell=False)
        if ret_val:
            raise exception.CloudbaseInitException(
                'Renaming interface "%(old_name)s" to "%(new_name)s" '
                'failed' % {'old_name': old_name, 'new_name': new_name})

    @staticmethod
    def _get_network_adapter(name):
        conn = wmi.WMI(moniker='//./root/cimv2')
        query = conn.Win32_NetworkAdapter(NetConnectionID=name)
        if not len(query):
            raise exception.CloudbaseInitException(
                "Network adapter not found: %s" % name)
        return query[0]

    @staticmethod
    def _set_static_network_config_legacy(name, address, netmask, gateway,
                                          dnsnameservers):
        if netaddr.valid_ipv6(address):
            LOG.warning("Setting IPv6 info not available on this system")
            return

        adapter_config = WindowsUtils._get_network_adapter(name).associators(
            wmi_result_class='Win32_NetworkAdapterConfiguration')[0]

        LOG.debug("Setting static IP address")
        (ret_val,) = adapter_config.EnableStatic([address], [netmask])
        if ret_val > 1:
            raise exception.CloudbaseInitException(
                "Cannot set static IP address on network adapter: %d" %
                ret_val)
        reboot_required = (ret_val == 1)

        if gateway:
            LOG.debug("Setting static gateways")
            (ret_val,) = adapter_config.SetGateways([gateway], [1])
            if ret_val > 1:
                raise exception.CloudbaseInitException(
                    "Cannot set gateway on network adapter: %d" % ret_val)
            reboot_required = reboot_required or ret_val == 1

        if dnsnameservers:
            LOG.debug("Setting static DNS servers")
            (ret_val,) = adapter_config.SetDNSServerSearchOrder(dnsnameservers)
            if ret_val > 1:
                raise exception.CloudbaseInitException(
                    "Cannot set DNS on network adapter: %d" % ret_val)
            reboot_required = reboot_required or ret_val == 1

        return reboot_required

    @staticmethod
    def _fix_network_adapter_dhcp(interface_name,
                                  enable_dhcp,
                                  address_family):
        enable_dhcp_value = 1 if enable_dhcp else 0

        conn = wmi.WMI(moniker='//./root/standardcimv2')
        net_interface = conn.MSFT_NetIPInterface(
            InterfaceAlias=interface_name, AddressFamily=address_family)
        if not len(net_interface):
            raise exception.ItemNotFoundException(
                'Network interface with name "%s" not found' %
                interface_name)
        net_interface = net_interface[0]
        net_interface.Dhcp = enable_dhcp_value
        net_interface.put()

    @staticmethod
    def _set_interface_dns(interface_name, dnsnameservers):
        # Import here to avoid loading errors on Windows versions where MI is
        # not available
        import mi

        conn = wmi.WMI(moniker='//./root/standardcimv2')
        # Requires Windows >= 6.2
        dns_client = conn.MSFT_DnsClientServerAddress(
            InterfaceAlias=interface_name)
        if not len(dns_client):
            raise exception.ItemNotFoundException(
                'Network interface with name "%s" not found' %
                interface_name)
        dns_client = dns_client[0]

        custom_options = [{
            u'name': u'ServerAddresses',
            u'value_type': mi.MI_ARRAY | mi.MI_STRING,
            u'value': dnsnameservers
        }]

        operation_options = {u'custom_options': custom_options}
        dns_client.put(operation_options=operation_options)

    def enable_network_adapter(self, name, enabled):
        adapter = self._get_network_adapter(name)
        if enabled:
            adapter.Enable()
        else:
            adapter.Disable()

    @staticmethod
    def _set_static_network_config(name, address, prefix_len, gateway):
        if netaddr.valid_ipv6(address):
            family = AF_INET6
        else:
            family = AF_INET

        # This is needed to avoid the error:
        # "Inconsistent parameters PolicyStore PersistentStore and
        # Dhcp Enabled"
        WindowsUtils._fix_network_adapter_dhcp(name, False, family)

        conn = wmi.WMI(moniker='//./root/standardcimv2')
        existing_addresses = conn.MSFT_NetIPAddress(
            AddressFamily=family, InterfaceAlias=name)
        for existing_address in existing_addresses:
            LOG.debug(
                "Removing existing IP address \"%(ip)s\" "
                "from adapter \"%(name)s\"",
                {"ip": existing_address.IPAddress, "name": name})
            existing_address.Delete_()

        existing_routes = conn.MSFT_NetRoute(
            AddressFamily=family, InterfaceAlias=name)
        for existing_route in existing_routes:
            LOG.debug(
                "Removing existing route \"%(route)s\" "
                "from adapter \"%(name)s\"",
                {"route": existing_route.DestinationPrefix, "name": name})
            existing_route.Delete_()

        conn.MSFT_NetIPAddress.create(
            AddressFamily=family, InterfaceAlias=name, IPAddress=address,
            PrefixLength=prefix_len, DefaultGateway=gateway)

    def set_static_network_config(self, name, address, prefix_len_or_netmask,
                                  gateway, dnsnameservers):
        ip_network = netaddr.IPNetwork(
            u"%s/%s" % (address, prefix_len_or_netmask))
        prefix_len = ip_network.prefixlen
        netmask = str(ip_network.netmask)

        if self.check_os_version(6, 2):
            self._set_static_network_config(
                name, address, prefix_len, gateway)
            if len(dnsnameservers):
                self._set_interface_dns(name, dnsnameservers)
        else:
            return self._set_static_network_config_legacy(
                name, address, netmask, gateway, dnsnameservers)

    def _get_network_team_manager(self):
        if self._network_team_manager:
            return self._network_team_manager

        team_managers = [
            "cloudbaseinit.utils.windows.netlbfo.NetLBFOTeamManager",
        ]

        cl = classloader.ClassLoader()
        for class_name in team_managers:
            try:
                cls = cl.load_class(class_name)
                if cls.is_available():
                    self._network_team_manager = cls()
                    return self._network_team_manager
            except Exception as ex:
                LOG.exception(ex)
        raise exception.ItemNotFoundException(
            "No network team manager available")

    def create_network_team(self, team_name, mode, load_balancing_algorithm,
                            members, mac_address, primary_nic_name=None,
                            primary_nic_vlan_id=None, lacp_timer=None):
        self._get_network_team_manager().create_team(
            team_name, mode, load_balancing_algorithm, members, mac_address,
            primary_nic_name, primary_nic_vlan_id, lacp_timer)

    def add_network_team_nic(self, team_name, nic_name, vlan_id):
        self._get_network_team_manager().add_team_nic(
            team_name, nic_name, vlan_id)

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

    def check_service_exists(self, service_name):
        LOG.debug("Checking if service exists: %s", service_name)
        try:
            with self._get_service_handle(service_name):
                return True
        except pywintypes.error as ex:
            if ex.winerror == winerror.ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise

    def get_service_status(self, service_name):
        LOG.debug("Getting service status for: %s", service_name)
        with self._get_service_handle(
                service_name, win32service.SERVICE_QUERY_STATUS) as hs:
            service_status = win32service.QueryServiceStatusEx(hs)
            state = service_status['CurrentState']

            return self._SERVICE_STATUS_MAP.get(
                state, WindowsUtils.SERVICE_STATUS_UNKNOWN)

    def get_service_start_mode(self, service_name):
        LOG.debug("Getting service start mode for: %s", service_name)
        with self._get_service_handle(
                service_name, win32service.SERVICE_QUERY_CONFIG) as hs:
            service_config = win32service.QueryServiceConfig(hs)

            start_type = service_config[1]
            return [k for k, v in self._SERVICE_START_TYPE_MAP.items()
                    if v == start_type][0]

    def set_service_start_mode(self, service_name, start_mode):
        # TODO(alexpilotti): Handle the "Delayed Start" case
        LOG.debug("Setting service start mode for: %s", service_name)
        start_type = self._get_win32_start_type(start_mode)

        with self._get_service_handle(
                service_name, win32service.SERVICE_CHANGE_CONFIG) as hs:
            win32service.ChangeServiceConfig(
                hs, win32service.SERVICE_NO_CHANGE,
                start_type, win32service.SERVICE_NO_CHANGE,
                None, None, False, None, None, None, None)

    def start_service(self, service_name):
        LOG.debug('Starting service %s', service_name)
        with self._get_service_handle(
                service_name, win32service.SERVICE_START) as hs:
            win32service.StartService(hs, service_name)

    def stop_service(self, service_name, wait=False):
        LOG.debug('Stopping service %s', service_name)
        with self._get_service_handle(
                service_name,
                win32service.SERVICE_STOP |
                win32service.SERVICE_QUERY_STATUS) as hs:
            win32service.ControlService(hs, win32service.SERVICE_CONTROL_STOP)
            if wait:
                while True:
                    service_status = win32service.QueryServiceStatusEx(hs)
                    state = service_status['CurrentState']
                    if state == win32service.SERVICE_STOPPED:
                        return
                    time.sleep(.1)

    @staticmethod
    @contextlib.contextmanager
    def _get_service_control_manager(
            scm_access=win32service.SC_MANAGER_CONNECT):
        hscm = win32service.OpenSCManager(None, None, scm_access)
        try:
            yield hscm
        finally:
            win32service.CloseServiceHandle(hscm)

    @staticmethod
    @contextlib.contextmanager
    def _get_service_handle(service_name,
                            service_access=win32service.SERVICE_QUERY_CONFIG,
                            scm_access=win32service.SC_MANAGER_CONNECT):
        with WindowsUtils._get_service_control_manager(scm_access) as hscm:
            hs = win32service.OpenService(hscm, service_name, service_access)
            try:
                yield hs
            finally:
                win32service.CloseServiceHandle(hs)

    @staticmethod
    def _get_win32_start_type(start_mode):
        start_type = WindowsUtils._SERVICE_START_TYPE_MAP.get(start_mode)
        if not start_type:
            raise exception.InvalidStateException(
                "Invalid service start mode: %s" % start_mode)
        return start_type

    def create_service(self, service_name, display_name, path, start_mode,
                       username=None, password=None):
        LOG.debug('Creating service %s', service_name)
        start_type = self._get_win32_start_type(start_mode)

        with WindowsUtils._get_service_control_manager(
                scm_access=win32service.SC_MANAGER_CREATE_SERVICE) as hscm:
            hs = win32service.CreateService(
                hscm, service_name, display_name,
                win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_WIN32_OWN_PROCESS,
                start_type,
                win32service.SERVICE_ERROR_NORMAL,
                path, None, False, None,
                username, password)
            win32service.CloseServiceHandle(hs)

    def delete_service(self, service_name):
        LOG.debug('Deleting service %s', service_name)
        with self._get_service_handle(
                service_name, win32service.SERVICE_ALL_ACCESS) as hs:
            win32service.DeleteService(hs)

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
            return None

        service_username = self.get_service_username(self._service_name)
        # Ignore builtin accounts
        if "\\" not in service_username:
            LOG.info("Skipping password reset, service running as a built-in "
                     "account: %s", service_username)
            return None
        domain, username = service_username.split('\\')
        if domain != ".":
            LOG.info("Skipping password reset, service running as a domain "
                     "account: %s", service_username)
            return None

        LOG.debug('Resetting password for service user: %s', service_username)
        maximum_length = self.get_maximum_password_length()
        password = self.generate_random_password(maximum_length)
        self.set_user_password(username, password)
        self.set_service_credentials(
            self._service_name, service_username, password)
        return domain, username, password

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

    def get_os_version(self):
        vi = Win32_OSVERSIONINFOEX_W()
        vi.dwOSVersionInfoSize = ctypes.sizeof(Win32_OSVERSIONINFOEX_W)
        ret_val = ntdll.RtlGetVersion(ctypes.byref(vi))
        if ret_val:
            raise exception.WindowsCloudbaseInitException(
                "RtlGetVersion failed with error: %s" % ret_val)
        return {"major_version": vi.dwMajorVersion,
                "minor_version": vi.dwMinorVersion,
                "build_number": vi.dwBuildNumber,
                "platform_id": vi.dwPlatformId,
                "csd_version": vi.szCSDVersion,
                "service_pack_major": vi.wServicePackMajor,
                "service_pack_minor": vi.wServicePackMinor,
                "suite_mask": vi.wSuiteMask,
                "product_type": vi.wProductType}

    def is_client_os(self):
        return self.get_os_version()["product_type"] == self.VER_NT_WORKSTATION

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

    def get_volume_path_names_by_mount_point(self, mount_point):
        max_volume_name_len = 50
        volume_name = ctypes.create_unicode_buffer(max_volume_name_len)

        if not kernel32.GetVolumeNameForVolumeMountPointW(
                six.text_type(mount_point), volume_name,
                max_volume_name_len):
            if kernel32.GetLastError() in [self.ERROR_INVALID_NAME,
                                           self.ERROR_PATH_NOT_FOUND]:
                raise exception.ItemNotFoundException(
                    "Mount point not found: %s" % mount_point)
            else:
                raise exception.WindowsCloudbaseInitException(
                    "Failed to get volume name for mount point: %s. "
                    "Error: %%r" % mount_point)

        volume_path_names_len = wintypes.DWORD(100)
        while True:
            volume_path_names = ctypes.create_unicode_buffer(
                volume_path_names_len.value)
            if not kernel32.GetVolumePathNamesForVolumeNameW(
                    volume_name, volume_path_names, volume_path_names_len,
                    ctypes.byref(volume_path_names_len)):
                if kernel32.GetLastError() == self.ERROR_MORE_DATA:
                    continue
                else:
                    raise exception.WindowsCloudbaseInitException(
                        "Failed to get path names for volume name: %s."
                        "Error: %%r" % volume_name.value)
            return [n for n in volume_path_names[
                :volume_path_names_len.value - 1].split('\0') if n]

    def generate_random_password(self, length):
        if length < 3:
            raise exception.CloudbaseInitException(
                "Password can not have less than 3 characters!")
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

    def get_logical_drives(self):
        buf_size = self.MAX_PATH
        buf = ctypes.create_unicode_buffer(buf_size + 1)
        buf_len = kernel32.GetLogicalDriveStringsW(buf_size, buf)
        if not buf_len:
            raise exception.WindowsCloudbaseInitException(
                "GetLogicalDriveStringsW failed: %r")

        return self._split_str_buf_list(buf, buf_len)

    def get_cdrom_drives(self):
        drives = self.get_logical_drives()
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

    def is_real_time_clock_utc(self):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            'SYSTEM\\CurrentControlSet\\Control\\'
                            'TimeZoneInformation') as key:
            try:
                utc = winreg.QueryValueEx(key, 'RealTimeIsUniversal')[0]
                return utc != 0
            except WindowsError as ex:
                if ex.winerror == 2:
                    return False
                raise

    def set_real_time_clock_utc(self, utc):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            'SYSTEM\\CurrentControlSet\\Control\\'
                            'TimeZoneInformation',
                            0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, 'RealTimeIsUniversal', 0,
                              winreg.REG_DWORD, 1 if utc else 0)

    def get_page_files(self):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            'SYSTEM\\CurrentControlSet\\Control\\'
                            'Session Manager\\Memory Management') as key:
            values = winreg.QueryValueEx(key, 'PagingFiles')[0]

        page_files = []
        for value in values:
            v = value.split(" ")
            path = v[0]
            min_size_mb = int(v[1]) if len(v) > 1 else 0
            max_size_mb = int(v[2]) if len(v) > 2 else 0
            page_files.append((path, min_size_mb, max_size_mb))
        return page_files

    def set_page_files(self, page_files):
        values = []
        for path, min_size_mb, max_size_mb in page_files:
            values.append("%s %d %d" % (path, min_size_mb, max_size_mb))

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            'SYSTEM\\CurrentControlSet\\Control\\'
                            'Session Manager\\Memory Management',
                            0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, 'PagingFiles', 0,
                              winreg.REG_MULTI_SZ, values)

    def enable_trim(self, enable):
        """Enables or disables TRIM delete notifications."""
        args = ["fsutil.exe", "behavior", "set", "disabledeletenotify",
                "0" if enable else "1"]
        (out, err, ret_val) = self.execute_system32_process(args)
        if ret_val:
            raise exception.CloudbaseInitException(
                'TRIM configurating failed.\nOutput: %(out)s\nError:'
                ' %(err)s' % {'out': out, 'err': err})

    def set_path_admin_acls(self, path):
        LOG.debug("Assigning admin ACLs on path: %s", path)
        # Sets ACLs for "NT AUTHORITY\SYSTEM" and "BUILTIN\Administrators"
        # TODO(alexpilotti): replace with SetNamedSecurityInfo
        (out, err, ret_val) = self.execute_system32_process([
            "icacls.exe", path, "/inheritance:r", "/grant:r",
            "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
        if ret_val:
            raise exception.CloudbaseInitException(
                'Failed to set path ACLs.\nOutput: %(out)s\nError:'
                ' %(err)s' % {'out': out, 'err': err})

    def take_path_ownership(self, path, username=None):
        if username:
            raise NotImplementedError()
        LOG.debug("Taking ownership of path: %s", path)
        # TODO(alexpilotti): replace with SetNamedSecurityInfo
        (out, err, ret_val) = self.execute_system32_process([
            "takeown.exe", "/F", path])
        if ret_val:
            raise exception.CloudbaseInitException(
                'Failed to take path ownership.\nOutput: %(out)s\nError:'
                ' %(err)s' % {'out': out, 'err': err})

    def check_dotnet_is_installed(self, version):
        # See: https://msdn.microsoft.com/en-us/library/hh925568(v=vs.110).aspx
        if str(version) != "4":
            raise exception.CloudbaseInitException(
                "Only checking for version 4 is supported at the moment")
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\'
                                'Microsoft\\NET Framework Setup\\NDP\\'
                                'v%s\\Full' % version) as key:
                return winreg.QueryValueEx(key, 'Install')[0] != 0
        except WindowsError as ex:
            if ex.winerror == 2:
                return False
            else:
                raise

    def get_file_version(self, path):
        info = win32api.GetFileVersionInfo(path, '\\')
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return (win32api.HIWORD(ms), win32api.LOWORD(ms),
                win32api.HIWORD(ls), win32api.LOWORD(ls))

    def get_default_script_exec_header(self):
        return constant.SCRIPT_HEADER_CMD
