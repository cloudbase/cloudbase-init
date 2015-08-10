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


import abc
import ctypes
from ctypes import windll
from ctypes import wintypes
import re

import six
import winioctlcon

from cloudbaseinit import exception


kernel32 = windll.kernel32


class Win32_DiskGeometry(ctypes.Structure):

    FixedMedia = 12

    _fields_ = [
        ('Cylinders', wintypes.LARGE_INTEGER),
        ('MediaType', wintypes.DWORD),
        ('TracksPerCylinder', wintypes.DWORD),
        ('SectorsPerTrack', wintypes.DWORD),
        ('BytesPerSector', wintypes.DWORD)
    ]


class Win32_DRIVE_LAYOUT_INFORMATION_MBR(ctypes.Structure):

    _fields_ = [
        ('Signature', wintypes.ULONG)
    ]


class GUID(ctypes.Structure):

    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", wintypes.BYTE * 8)
    ]

    def __init__(self, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8):
        self.data1 = l
        self.data2 = w1
        self.data3 = w2
        self.data4[0] = b1
        self.data4[1] = b2
        self.data4[2] = b3
        self.data4[3] = b4
        self.data4[4] = b5
        self.data4[5] = b6
        self.data4[6] = b7
        self.data4[7] = b8


class Win32_DRIVE_LAYOUT_INFORMATION_GPT(ctypes.Structure):

    _fields_ = [
        ('DiskId', GUID),
        ('StartingUsableOffset', wintypes.LARGE_INTEGER),
        ('UsableLength', wintypes.LARGE_INTEGER),
        ('MaxPartitionCount', wintypes.ULONG)
    ]


class DRIVE_FORMAT(ctypes.Union):

    _fields_ = [
        ('Mbr', Win32_DRIVE_LAYOUT_INFORMATION_MBR),
        ('Gpt', Win32_DRIVE_LAYOUT_INFORMATION_GPT)
    ]


class Win32_PARTITION_INFORMATION_MBR(ctypes.Structure):

    _fields_ = [
        ('PartitionType', wintypes.BYTE),
        ('BootIndicator', wintypes.BOOLEAN),
        ('RecognizedPartition', wintypes.BOOLEAN),
        ('HiddenSectors', wintypes.DWORD)
    ]


class Win32_PARTITION_INFORMATION_GPT(ctypes.Structure):

    _fields_ = [
        ('PartitionType', GUID),
        ('PartitionId', GUID),
        ('Attributes', wintypes.ULARGE_INTEGER),
        ('Name', wintypes.WCHAR * 36)
    ]


class PARTITION_INFORMATION(ctypes.Union):

    _fields_ = [
        ('Mbr', Win32_PARTITION_INFORMATION_MBR),
        ('Gpt', Win32_PARTITION_INFORMATION_GPT)
    ]


class Win32_PARTITION_INFORMATION_EX(ctypes.Structure):

    _anonymous_ = ('PartitionInformation',)

    _fields_ = [
        ('PartitionStyle', wintypes.DWORD),
        ('StartingOffset', wintypes.LARGE_INTEGER),
        ('PartitionLength', wintypes.LARGE_INTEGER),
        ('PartitionNumber', wintypes.DWORD),
        ('RewritePartition', wintypes.BOOLEAN),
        ('PartitionInformation', PARTITION_INFORMATION)
    ]


class Win32_DRIVE_LAYOUT_INFORMATION_EX(ctypes.Structure):

    _anonymous_ = ('DriveFormat',)

    _fields_ = [
        ('PartitionStyle', wintypes.DWORD),
        ('PartitionCount', wintypes.DWORD),
        ('DriveFormat', DRIVE_FORMAT),
        ('PartitionEntry', Win32_PARTITION_INFORMATION_EX * 128)
    ]


@six.add_metaclass(abc.ABCMeta)
class BaseDevice(object):
    """Base class for devices like disks and partitions.

    It has common methods for getting physical disk geometry,
    opening/closing the device and also seeking through it
    for reading certain amounts of bytes.
    """

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 1
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_READONLY = 1
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    FILE_BEGIN = 0
    INVALID_SET_FILE_POINTER = 0xFFFFFFFF

    def __init__(self, path):
        self._path = path

        self._handle = None
        self._sector_size = None
        self._disk_size = None
        self.fixed = None

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, self._path)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _get_geometry(self):
        """Get details about the disk size bounds."""
        geom = Win32_DiskGeometry()
        bytes_returned = wintypes.DWORD()
        ret_val = kernel32.DeviceIoControl(
            self._handle,
            winioctlcon.IOCTL_DISK_GET_DRIVE_GEOMETRY,
            0,
            0,
            ctypes.byref(geom),
            ctypes.sizeof(geom),
            ctypes.byref(bytes_returned),
            0)

        if not ret_val:
            raise exception.WindowsCloudbaseInitException(
                "Cannot get disk geometry: %r")

        _sector_size = geom.BytesPerSector
        _disk_size = (geom.Cylinders * geom.TracksPerCylinder *
                      geom.SectorsPerTrack * geom.BytesPerSector)
        fixed = geom.MediaType == Win32_DiskGeometry.FixedMedia
        return _sector_size, _disk_size, fixed

    def _seek(self, offset):
        high = wintypes.DWORD(offset >> 32)
        low = wintypes.DWORD(offset & 0xFFFFFFFF)

        ret_val = kernel32.SetFilePointer(self._handle, low,
                                          ctypes.byref(high),
                                          self.FILE_BEGIN)
        if ret_val == self.INVALID_SET_FILE_POINTER:
            raise exception.WindowsCloudbaseInitException(
                "Seek error: %r")

    def _read(self, size):
        buff = ctypes.create_string_buffer(size)
        bytes_read = wintypes.DWORD()
        ret_val = kernel32.ReadFile(self._handle, buff, size,
                                    ctypes.byref(bytes_read), 0)
        if not ret_val:
            raise exception.WindowsCloudbaseInitException(
                "Read exception: %r")
        return buff.raw[:bytes_read.value]    # all bytes without the null byte

    def open(self):
        handle = kernel32.CreateFileW(
            ctypes.c_wchar_p(self._path),
            self.GENERIC_READ,
            self.FILE_SHARE_READ,
            0,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_READONLY,
            0)
        if handle == self.INVALID_HANDLE_VALUE:
            raise exception.WindowsCloudbaseInitException(
                'Cannot open file: %r')
        self._handle = handle
        self._sector_size, self._disk_size, self.fixed =\
            self._get_geometry()

    def close(self):
        if self._handle:
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def seek(self, offset):
        """Drive geometry safe seek.

        Seek for a given offset and return the valid set one.
        """
        safe_offset = int(offset / self._sector_size) * self._sector_size
        self._seek(safe_offset)
        return safe_offset

    def read(self, size, skip=0):
        """Drive geometry safe read.

        Read and extract exactly the requested content.
        """
        # Compute a size to fit both of the bytes we need to skip and
        # also the minimum read size.
        total = size + skip
        safe_size = ((int(total / self._sector_size) +
                      bool(total % self._sector_size)) * self._sector_size)
        content = self._read(safe_size)
        return content[skip:total]

    @abc.abstractmethod
    def size(self):
        """Returns the size in bytes of the actual opened device."""


class Disk(BaseDevice):
    """Disk class with seek/read support.

    It also has the capability of obtaining partition objects.
    """

    PARTITION_ENTRY_UNUSED = 0
    PARTITION_STYLE_MBR = 0
    PARTITION_STYLE_GPT = 1

    def _get_layout(self):
        layout = Win32_DRIVE_LAYOUT_INFORMATION_EX()
        bytes_returned = wintypes.DWORD()
        ret_val = kernel32.DeviceIoControl(
            self._handle,
            winioctlcon.IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
            0,
            0,
            ctypes.byref(layout),
            ctypes.sizeof(layout),
            ctypes.byref(bytes_returned),
            0)

        if not ret_val:
            raise exception.WindowsCloudbaseInitException(
                "Cannot get disk layout: %r")
        return layout

    def _get_partition_indexes(self, layout):
        partition_style = layout.PartitionStyle
        if partition_style not in (self.PARTITION_STYLE_MBR,
                                   self.PARTITION_STYLE_GPT):
            raise exception.CloudbaseInitException(
                "Invalid partition style %r" % partition_style)
        # If is GPT, then the count reflects the actual number of partitions
        # but if is MBR, then the number of partitions is a multiple of 4
        # and just the indexes for the used partitions must be saved.
        partition_indexes = []
        if partition_style == self.PARTITION_STYLE_GPT:
            partition_indexes.extend(range(layout.PartitionCount))
        else:
            for idx in range(layout.PartitionCount):
                if (layout.PartitionEntry[idx].Mbr.PartitionType !=
                        self.PARTITION_ENTRY_UNUSED):
                    partition_indexes.append(idx)
        return partition_indexes

    def partitions(self):
        """Return a list of partition objects available on disk."""
        layout = self._get_layout()
        partition_indexes = self._get_partition_indexes(layout)
        # Create and return the partition objects containing their sizes.
        partitions = []
        disk_index = re.search(r"(disk|drive)(\d+)", self._path,
                               re.I | re.M).group(2)
        for partition_index in partition_indexes:
            path = r'\\?\GLOBALROOT\Device\Harddisk{}\Partition{}'.format(
                disk_index, partition_index + 1)
            size = layout.PartitionEntry[partition_index].PartitionLength
            partition = Partition(path, size)
            partitions.append(partition)
        return partitions

    @property
    def size(self):
        return self._disk_size


class Partition(BaseDevice):
    """Partition class with seek/read support."""

    def __init__(self, path, size):
        super(Partition, self).__init__(path)
        self._partition_size = size

    @property
    def size(self):
        return self._partition_size
