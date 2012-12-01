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


class Win32_DiskGeometry(ctypes.Structure):
    FixedMedia = 12

    _fields_ = [
        ('Cylinders',         wintypes.LARGE_INTEGER),
        ('MediaType',         wintypes.DWORD),
        ('TracksPerCylinder', wintypes.DWORD),
        ('SectorsPerTrack',   wintypes.DWORD),
        ('BytesPerSector',    wintypes.DWORD),
    ]


class PhysicalDisk(object):
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 1
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_READONLY = 1
    INVALID_HANDLE_VALUE = -1
    IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000
    FILE_BEGIN = 0
    INVALID_SET_FILE_POINTER = 0xFFFFFFFFL

    def __init__(self, path):
        self._path = path
        self._handle = 0
        self._geom = None

    def open(self):
        if self._handle:
            self.close()

        handle = kernel32.CreateFileW(
            ctypes.c_wchar_p(self._path),
            self.GENERIC_READ,
            self.FILE_SHARE_READ,
            0,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_READONLY,
            0)
        if handle == self.INVALID_HANDLE_VALUE:
            raise Exception('Cannot open file')
        self._handle = handle

    def close(self):
        kernel32.CloseHandle(self._handle)
        self._handle = 0
        self._geom = None

    def get_geometry(self):
        if not self._geom:
            geom = Win32_DiskGeometry()
            bytes_returned = wintypes.DWORD()
            ret_val = kernel32.DeviceIoControl(
                self._handle,
                self.IOCTL_DISK_GET_DRIVE_GEOMETRY,
                0,
                0,
                ctypes.byref(geom),
                ctypes.sizeof(geom),
                ctypes.byref(bytes_returned),
                0)
            if not ret_val:
                raise Exception("Cannot get disk geometry")
            self._geom = geom
        return self._geom

    def seek(self, offset):
        high = wintypes.DWORD(offset >> 32)
        low = wintypes.DWORD(offset & 0xFFFFFFFFL)

        ret_val = kernel32.SetFilePointer(self._handle, low,
            ctypes.byref(high), self.FILE_BEGIN)
        if ret_val == self.INVALID_SET_FILE_POINTER:
            raise Exception("Seek error")

    def read(self, bytes_to_read):
        buf = ctypes.create_string_buffer(bytes_to_read)
        bytes_read = wintypes.DWORD()
        ret_val = kernel32.ReadFile(self._handle, buf, bytes_to_read,
            ctypes.byref(bytes_read), 0)
        if not ret_val:
            raise Exception("Read exception")
        return (buf, bytes_read.value)
