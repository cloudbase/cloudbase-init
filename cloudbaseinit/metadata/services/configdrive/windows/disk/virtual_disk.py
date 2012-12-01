# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import ctypes

from ctypes import windll
from ctypes import wintypes

kernel32 = windll.kernel32
virtdisk = windll.virtdisk


class Win32_GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)]


def get_WIN32_VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT():
    guid = Win32_GUID()
    guid.Data1 = 0xec984aec
    guid.Data2 = 0xa0f9
    guid.Data3 = 0x47e9
    ByteArray8 = wintypes.BYTE * 8;
    guid.Data4 = ByteArray8(0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b)
    return guid


class Win32_VIRTUAL_STORAGE_TYPE(ctypes.Structure):
    _fields_ = [
        ('DeviceId', wintypes.DWORD),
        ('VendorId', Win32_GUID)
    ]


class VirtualDisk(object):
    VIRTUAL_STORAGE_TYPE_DEVICE_ISO = 1
    VIRTUAL_DISK_ACCESS_ATTACH_RO = 0x10000
    VIRTUAL_DISK_ACCESS_READ = 0xd0000
    OPEN_VIRTUAL_DISK_FLAG_NONE = 0
    DETACH_VIRTUAL_DISK_FLAG_NONE = 0
    ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY = 1
    ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 2

    def __init__(self, path):
        self._path = path
        self._handle = 0

    def open(self):
        if self._handle:
            self.close()

        vst = Win32_VIRTUAL_STORAGE_TYPE()
        vst.DeviceId = self.VIRTUAL_STORAGE_TYPE_DEVICE_ISO
        vst.VendorId = get_WIN32_VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT()

        handle = wintypes.HANDLE()
        ret_val = virtdisk.OpenVirtualDisk(ctypes.byref(vst), ctypes.c_wchar_p(self._path),
            self.VIRTUAL_DISK_ACCESS_ATTACH_RO | self.VIRTUAL_DISK_ACCESS_READ,
            self.OPEN_VIRTUAL_DISK_FLAG_NONE, 0, ctypes.byref(handle))
        if ret_val:
            raise Exception("Cannot open virtual disk")
        self._handle = handle

    def attach(self):
        ret_val = virtdisk.AttachVirtualDisk(self._handle, 0,
            self.ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY,
            0, 0, 0)
        if ret_val:
            raise Exception("Cannot attach virtual disk")

    def detach(self):
        ret_val = virtdisk.DetachVirtualDisk(self._handle,
            self.DETACH_VIRTUAL_DISK_FLAG_NONE, 0)
        if ret_val:
            raise Exception("Cannot detach virtual disk")

    def get_physical_path(self):
        buf = ctypes.create_unicode_buffer(1024)
        bufLen = wintypes.DWORD(ctypes.sizeof(buf));
        ret_val = virtdisk.GetVirtualDiskPhysicalPath(self._handle,
            ctypes.byref(bufLen), buf)
        if ret_val:
            raise Exception("Cannot get virtual disk physical path")
        return buf.value

    def get_cdrom_drive_mount_point(self):

        mount_point = None

        buf = ctypes.create_unicode_buffer(2048)
        buf_len = kernel32.GetLogicalDriveStringsW(
            ctypes.sizeof(buf) / ctypes.sizeof(wintypes.WCHAR), buf)
        if not buf_len:
            raise Exception("Cannot enumerate logical devices")

        cdrom_dev = self.get_physical_path().rsplit('\\')[-1].upper()

        i = 0
        while not mount_point and i < buf_len:
            curr_drive = ctypes.wstring_at(ctypes.addressof(buf) + \
                i * ctypes.sizeof(wintypes.WCHAR))[:-1]

            dev = ctypes.create_unicode_buffer(2048)
            ret_val = kernel32.QueryDosDeviceW(curr_drive, dev,
                ctypes.sizeof(dev) / ctypes.sizeof(wintypes.WCHAR))
            if not ret_val:
                raise Exception("Cannot query NT device")

            if dev.value.rsplit('\\')[-1].upper() == cdrom_dev:
                mount_point = curr_drive
            else:
                i += len(curr_drive) + 2

        return mount_point

    def close(self):
        kernel32.CloseHandle(self._handle)
        self._handle = 0
