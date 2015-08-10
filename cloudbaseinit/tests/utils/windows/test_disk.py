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

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


class BaseTestDevice(unittest.TestCase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()
        _module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._ctypes_mock,
             'ctypes.windll': mock.MagicMock(),
             'ctypes.wintypes': mock.MagicMock(),
             'winioctlcon': mock.MagicMock()})
        _module_patcher.start()
        self.addCleanup(_module_patcher.stop)

        self.disk = importlib.import_module(
            "cloudbaseinit.utils.windows.disk")
        self.mock_dword = mock.Mock()
        self._ctypes_mock.wintypes.DWORD = self.mock_dword
        self.disk.kernel32 = mock.MagicMock()

        self.geom = mock.Mock()
        self.geom.MediaType = self.disk.Win32_DiskGeometry.FixedMedia = 12
        self.geom.Cylinders = 2
        self.geom.TracksPerCylinder = 5
        self.geom.SectorsPerTrack = 512
        self.geom.BytesPerSector = 512


class TestBaseDevice(BaseTestDevice, testutils.CloudbaseInitTestBase):

    def setUp(self):
        super(TestBaseDevice, self).setUp()

        class FinalBaseDevice(self.disk.BaseDevice):
            def size(self):
                return 0

        self.fake_path = mock.sentinel.fake_path
        self._device_class = FinalBaseDevice(
            path=self.fake_path)
        self._device_class._sector_size = self.geom.BytesPerSector
        self._device_class._disk_size = 2 * 5 * 512 * 512

    def _test_open(self, exc):
        if exc:
            self.disk.kernel32.CreateFileW.return_value = \
                self._device_class.INVALID_HANDLE_VALUE

            with self.assert_raises_windows_message(
                    "Cannot open file: %r", 100):
                self._device_class.open()
        else:
            self._device_class.open()

            self.disk.kernel32.CreateFileW.assert_called_once_with(
                self._ctypes_mock.c_wchar_p.return_value,
                self._device_class.GENERIC_READ,
                self._device_class.FILE_SHARE_READ,
                0, self._device_class.OPEN_EXISTING,
                self._device_class.FILE_ATTRIBUTE_READONLY, 0
            )
            self._ctypes_mock.c_wchar_p.assert_called_once_with(self.fake_path)

            self.assertEqual(
                self.disk.kernel32.CreateFileW.return_value,
                self._device_class._handle)

    def test_open(self):
        self._test_open(exc=False)

    def test_open_exception(self):
        self._test_open(exc=True)

    def test_close(self):
        self._device_class._handle = mock.sentinel._handle

        self._device_class.close()
        self.disk.kernel32.CloseHandle.assert_called_once_with(
            mock.sentinel._handle)
        self.assertEqual(None, self._device_class._handle)

    def _test_get_geometry(self, ret_val, last_error=None):
        mock_disk_geom = self.disk.Win32_DiskGeometry
        mock_disk_geom.side_effect = None
        mock_disk_geom.return_value = self.geom

        mock_DeviceIoControl = self.disk.kernel32.DeviceIoControl
        expect_byref = [mock.call(self.geom),
                        mock.call(
                            self.mock_dword.return_value)]
        self.disk.kernel32.DeviceIoControl.return_value = ret_val

        if not ret_val:
            with self.assert_raises_windows_message(
                    "Cannot get disk geometry: %r", last_error):
                self._device_class._get_geometry()
        else:
            response = self._device_class._get_geometry()
            self.mock_dword.assert_called_once_with()
            mock_DeviceIoControl.assert_called_once_with(
                self._device_class._handle,
                self.disk.winioctlcon.IOCTL_DISK_GET_DRIVE_GEOMETRY, 0, 0,
                self._ctypes_mock.byref.return_value,
                self._ctypes_mock.sizeof.return_value,
                self._ctypes_mock.byref.return_value, 0)

            self.assertEqual(expect_byref,
                             self._ctypes_mock.byref.call_args_list)
            self.assertEqual((self._device_class._sector_size,
                              self._device_class._disk_size, True),
                             response)

    def test_get_geometry(self):
        self._test_get_geometry(ret_val=mock.sentinel.ret_val)

    def test_get_geometry_exception(self):
        self._test_get_geometry(ret_val=0, last_error=100)

    def _test__seek(self, exc):
        expect_DWORD = [mock.call(0), mock.call(1)]
        if exc:
            self.disk.kernel32.SetFilePointer.return_value = \
                self._device_class.INVALID_SET_FILE_POINTER
            with self.assert_raises_windows_message(
                    "Seek error: %r", 100):
                self._device_class._seek(1)
        else:
            self._device_class._seek(1)
            self.disk.kernel32.SetFilePointer.assert_called_once_with(
                self._device_class._handle,
                self.mock_dword.return_value,
                self._ctypes_mock.byref.return_value,
                self._device_class.FILE_BEGIN)
            self._ctypes_mock.byref.assert_called_once_with(
                self.mock_dword.return_value)

            self.assertEqual(expect_DWORD,
                             self.mock_dword.call_args_list)

    def test__seek(self):
        self._test__seek(exc=False)

    def test__seek_exception(self):
        self._test__seek(exc=True)

    def test_seek(self):
        offset = self._device_class.seek(1025)
        self.assertEqual(1024, offset)

    def _test__read(self, ret_val, last_error=None):
        bytes_to_read = mock.sentinel.bytes_to_read
        self.disk.kernel32.ReadFile.return_value = ret_val

        if not ret_val:
            with self.assert_raises_windows_message(
                    "Read exception: %r", last_error):
                self._device_class._read(bytes_to_read)
        else:
            response = self._device_class._read(bytes_to_read)
            mock_buffer = self._ctypes_mock.create_string_buffer

            mock_buffer.assert_called_once_with(bytes_to_read)
            self.mock_dword.assert_called_once_with()
            self.disk.kernel32.ReadFile.assert_called_once_with(
                self._device_class._handle,
                mock_buffer.return_value,
                bytes_to_read, self._ctypes_mock.byref.return_value, 0)

            self._ctypes_mock.byref.assert_called_once_with(
                self.mock_dword.return_value)

            self.assertEqual(
                mock_buffer.return_value.raw[
                    :self.mock_dword.return_value.value], response)

    def test__read(self):
        self._test__read(ret_val=mock.sentinel.ret_val)

    def test__read_exception(self):
        self._test__read(ret_val=None, last_error=100)

    def test_read(self):
        _read_func = mock.Mock()
        mock_content = mock.MagicMock()
        _read_func.return_value = mock_content
        self._device_class._read = _read_func
        response = self._device_class.read(512, 10)
        self._device_class._read.assert_called_once_with(1024)
        self.assertEqual(response, mock_content[10, 522])


class TestDisk(BaseTestDevice, testutils.CloudbaseInitTestBase):

    def setUp(self):
        super(TestDisk, self).setUp()
        self.fake_disk_path = mock.sentinel.fake_disk_path
        self._disk_class = self.disk.Disk(
            path=self.fake_disk_path)
        self._disk_class._disk_size = 2 * 5 * 512 * 512

    @mock.patch("cloudbaseinit.utils.windows.disk"
                ".Win32_DRIVE_LAYOUT_INFORMATION_EX")
    def _test_get_layout(self, mock_layout_struct, fail=False):
        mock_layout = mock.Mock()
        mock_layout_struct.return_value = mock_layout
        mock_devio = self.disk.kernel32.DeviceIoControl

        if fail:
            mock_devio.return_value = 0
            with self.assert_raises_windows_message(
                    "Cannot get disk layout: %r", 100):
                self._disk_class._get_layout()
            return
        mock_devio.return_value = 1
        response = self._disk_class._get_layout()

        mock_devio.assert_called_once_with(
            self._disk_class._handle,
            self.disk.winioctlcon.IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
            0,
            0,
            self._ctypes_mock.byref(mock_layout),
            self._ctypes_mock.sizeof(mock_layout),
            self._ctypes_mock.byref(self.mock_dword.return_value),
            0)
        self.assertEqual(mock_layout, response)

    def test_get_layout_fail(self):
        self._test_get_layout(fail=True)

    def test_get_layout(self):
        self._test_get_layout()

    def _test_get_partition_indexes(self, fail=False, gpt=True):
        layout = mock.MagicMock()

        if fail:
            with self.assertRaises(exception.CloudbaseInitException):
                self._disk_class._get_partition_indexes(layout)
            return

        part_style = (self._disk_class.PARTITION_STYLE_GPT if gpt
                      else self._disk_class.PARTITION_STYLE_MBR)
        layout.PartitionStyle = part_style
        count = 8
        layout.PartitionCount = count
        if gpt:
            expected = list(range(count))
        else:
            layout.PartitionEntry = [mock.Mock() for _ in range(count)]
            layout.PartitionEntry[-1].Mbr.PartitionType = \
                self._disk_class.PARTITION_ENTRY_UNUSED
            expected = list(range(count - 1))
        response = self._disk_class._get_partition_indexes(layout)
        self.assertEqual(expected, response)

    def test_get_partition_indexes_fail(self):
        self._test_get_partition_indexes(fail=True)

    def test_get_partition_indexes_gpt(self):
        self._test_get_partition_indexes()

    def test_get_partition_indexes_mbr(self):
        self._test_get_partition_indexes(gpt=False)

    @mock.patch("cloudbaseinit.utils.windows.disk"
                ".Partition")
    @mock.patch("cloudbaseinit.utils.windows.disk"
                ".Disk._get_partition_indexes")
    @mock.patch("cloudbaseinit.utils.windows.disk"
                ".Disk._get_layout")
    def test_partitions(self, mock_get_layout, mock_get_partition_indexes,
                        mock_partition):
        size = 512
        layout = mock.MagicMock()
        layout.PartitionEntry[0].PartitionLength = size
        indexes = [0, 1, 2]
        mock_get_layout.return_value = layout
        mock_get_partition_indexes.return_value = indexes
        self._disk_class._path = r"\\?\GLOBALROOT\Device\Harddisk0"

        response = self._disk_class.partitions()
        mock_get_layout.assert_called_once_with()
        mock_get_partition_indexes.assert_called_once_with(layout)
        paths = [r"\\?\GLOBALROOT\Device\Harddisk{}\Partition{}".format(
                 0, idx + 1) for idx in indexes]
        calls = [mock.call(path, size) for path in paths]
        mock_partition.assert_has_calls(calls)
        expected = [mock_partition(path, size) for path in paths]
        self.assertEqual(expected, response)


class TestPartition(unittest.TestCase):

    def setUp(self):
        _module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': mock.MagicMock(),
             'winioctlcon': mock.MagicMock()})
        _module_patcher.start()
        self.addCleanup(_module_patcher.stop)
        self.disk = importlib.import_module(
            "cloudbaseinit.utils.windows.disk")

    def test_size(self):
        size = mock.sentinel.size
        partition = self.disk.Partition(mock.Mock(), size)
        self.assertEqual(size, partition.size)
