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

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception as cbinit_exception
from cloudbaseinit.tests import testutils


class WindowsPhysicalDiskUtilsTests(testutils.CloudbaseInitTestBase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._ctypes_mock})

        self._module_patcher.start()

        self.physical_disk = importlib.import_module(
            "cloudbaseinit.utils.windows.physical_disk")

        self.fake_path = mock.sentinel.fake_path
        self._phys_disk_class = self.physical_disk.PhysicalDisk(
            path=self.fake_path)

        self.physical_disk.kernel32 = mock.MagicMock()

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('cloudbaseinit.utils.windows.physical_disk'
                '.PhysicalDisk.close')
    def _test_open(self, mock_close, _handle, exception):
        self._phys_disk_class._handle = _handle

        if exception:
            self.physical_disk.kernel32.CreateFileW.return_value = \
                self._phys_disk_class.INVALID_HANDLE_VALUE

            self.assertRaises(cbinit_exception.CloudbaseInitException,
                              self._phys_disk_class.open)

        else:
            self._phys_disk_class.open()

            self.physical_disk.kernel32.CreateFileW.assert_called_once_with(
                self._ctypes_mock.c_wchar_p.return_value,
                self._phys_disk_class.GENERIC_READ,
                self._phys_disk_class.FILE_SHARE_READ,
                0, self._phys_disk_class.OPEN_EXISTING,
                self._phys_disk_class.FILE_ATTRIBUTE_READONLY, 0
            )
            self._ctypes_mock.c_wchar_p.assert_called_once_with(self.fake_path)

            self.assertEqual(
                self.physical_disk.kernel32.CreateFileW.return_value,
                self._phys_disk_class._handle)

            if _handle:
                mock_close.assert_called_once_with()

    def test_open(self):
        self._test_open(_handle=None, exception=None)

    def test_open_exeption(self):
        self._test_open(_handle=None, exception=True)

    def test_open_with_close(self):
        self._test_open(_handle=mock.sentinel._handle, exception=True)

    def test_close(self):
        self._phys_disk_class._handle = mock.sentinel._handle
        self._phys_disk_class._geom = mock.sentinel._geom

        self._phys_disk_class.close()

        self.physical_disk.kernel32.CloseHandle.assert_called_once_with(
            mock.sentinel._handle)

        self.assertEqual(0, self._phys_disk_class._handle)
        self.assertEqual(None, self._phys_disk_class._geom)

    @mock.patch('cloudbaseinit.utils.windows.physical_disk'
                '.Win32_DiskGeometry')
    def _test_get_geometry(self, mock_Win32_DiskGeometry, _geom, ret_val,
                           last_error=None):
        mock_DeviceIoControl = self.physical_disk.kernel32.DeviceIoControl
        expect_byref = [mock.call(mock_Win32_DiskGeometry.return_value),
                        mock.call(
                            self._ctypes_mock.wintypes.DWORD.return_value)]

        self._phys_disk_class._geom = _geom
        self.physical_disk.kernel32.DeviceIoControl.return_value = ret_val

        if not ret_val:
            with self.assert_raises_windows_message(
                    "Cannot get disk geometry: %r", last_error):
                self._phys_disk_class.get_geometry()
        elif _geom:
            response = self._phys_disk_class.get_geometry()
            self.assertEqual(_geom, response)

        else:
            response = self._phys_disk_class.get_geometry()

            mock_Win32_DiskGeometry.assert_called_once_with()
            self._ctypes_mock.wintypes.DWORD.assert_called_once_with()

            mock_DeviceIoControl.assert_called_once_with(
                self._phys_disk_class._handle,
                self._phys_disk_class.IOCTL_DISK_GET_DRIVE_GEOMETRY, 0, 0,
                self._ctypes_mock.byref.return_value,
                self._ctypes_mock.sizeof.return_value,
                self._ctypes_mock.byref.return_value, 0)

            self.assertEqual(expect_byref,
                             self._ctypes_mock.byref.call_args_list)

            self.assertEqual(mock_Win32_DiskGeometry.return_value,
                             self._phys_disk_class._geom)
            self.assertEqual(self._phys_disk_class._geom, response)

    def test_get_geometry(self):
        self._test_get_geometry(_geom=mock.sentinel._geom,
                                ret_val=mock.sentinel.ret_val)

    def test_get_geometry_no_geom(self):
        self._test_get_geometry(_geom=None,
                                ret_val=mock.sentinel.ret_val,
                                last_error=100)

    def test_get_geometry_no_geom_exception(self):
        self._test_get_geometry(_geom=None, ret_val=None,
                                last_error=100)

    def _test_seek(self, exception):
        expect_DWORD = [mock.call(0), mock.call(1)]
        if exception:
            self.physical_disk.kernel32.SetFilePointer.return_value = \
                self._phys_disk_class.INVALID_SET_FILE_POINTER

            self.assertRaises(cbinit_exception.CloudbaseInitException,
                              self._phys_disk_class.seek, 1)
        else:
            self._phys_disk_class.seek(1)
            self.physical_disk.kernel32.SetFilePointer.assert_called_once_with(
                self._phys_disk_class._handle,
                self._ctypes_mock.wintypes.DWORD.return_value,
                self._ctypes_mock.byref.return_value,
                self._phys_disk_class.FILE_BEGIN)
            self._ctypes_mock.byref.assert_called_once_with(
                self._ctypes_mock.wintypes.DWORD.return_value)

            self.assertEqual(expect_DWORD,
                             self._ctypes_mock.wintypes.DWORD.call_args_list)

    def test_seek(self):
        self._test_seek(exception=False)

    def test_seek_exception(self):
        self._test_seek(exception=True)

    def _test_read(self, ret_val, last_error=None):
        bytes_to_read = mock.sentinel.bytes_to_read
        self.physical_disk.kernel32.ReadFile.return_value = ret_val

        if not ret_val:
            with self.assert_raises_windows_message(
                    "Read exception: %r", last_error):
                self._phys_disk_class.read(bytes_to_read)
        else:
            response = self._phys_disk_class.read(bytes_to_read)

            self._ctypes_mock.create_string_buffer.assert_called_once_with(
                bytes_to_read)
            self._ctypes_mock.wintypes.DWORD.assert_called_once_with()
            self.physical_disk.kernel32.ReadFile.assert_called_once_with(
                self._phys_disk_class._handle,
                self._ctypes_mock.create_string_buffer.return_value,
                bytes_to_read, self._ctypes_mock.byref.return_value, 0)

            self._ctypes_mock.byref.assert_called_once_with(
                self._ctypes_mock.wintypes.DWORD.return_value)

            self.assertEqual(
                (self._ctypes_mock.create_string_buffer.return_value,
                 self._ctypes_mock.wintypes.DWORD.return_value.value),
                response)

    def test_read(self):
        self._test_read(ret_val=mock.sentinel.ret_val)

    def test_read_exception(self):
        self._test_read(ret_val=None, last_error=100)
