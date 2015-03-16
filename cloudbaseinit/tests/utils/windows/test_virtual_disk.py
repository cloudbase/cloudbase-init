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

from cloudbaseinit.tests import testutils


class WindowsVirtualDiskUtilsTests(testutils.CloudbaseInitTestBase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._ctypes_mock})

        self._module_patcher.start()

        self.virtual_disk = importlib.import_module(
            "cloudbaseinit.utils.windows.virtual_disk")

        self.fake_path = mock.sentinel.fake_path
        self._vdisk_class = self.virtual_disk.VirtualDisk(path=self.fake_path)

        self.virtual_disk.virtdisk = None
        self.virtual_disk.kernel32 = mock.MagicMock()

    def tearDown(self):
        self._module_patcher.stop()

    def test_load_virtdisk_dll(self):
        self._vdisk_class._load_virtdisk_dll()

        self.assertEqual(self._ctypes_mock.windll.virtdisk,
                         self.virtual_disk.virtdisk)

    @mock.patch('cloudbaseinit.utils.windows.virtual_disk'
                '.Win32_VIRTUAL_STORAGE_TYPE')
    @mock.patch('cloudbaseinit.utils.windows.virtual_disk'
                '.get_WIN32_VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT')
    @mock.patch('cloudbaseinit.utils.windows.virtual_disk'
                '.VirtualDisk._load_virtdisk_dll')
    @mock.patch('cloudbaseinit.utils.windows.virtual_disk'
                '.VirtualDisk.close')
    def _test_open(self, mock_close, mock_load_virtdisk_dll,
                   mock_get_virtual_storage_type_vendor,
                   mock_Win32_VIRTUAL_STORAGE_TYPE, handle, ret_val):

        virtdisk = self._ctypes_mock.windll.virtdisk
        virtdisk.OpenVirtualDisk.return_value = ret_val
        self.virtual_disk.virtdisk = virtdisk

        self._vdisk_class._handle = None
        if handle:
            self._vdisk_class._handle = handle

        if ret_val:
            with self.assert_raises_windows_message(
                    "Cannot open virtual disk: %r",
                    ret_val):
                self._vdisk_class.open()
        else:
            self._vdisk_class.open()
            if handle:
                mock_close.assert_called_once_with()

            mock_load_virtdisk_dll.assert_called_once_with()

            mock_Win32_VIRTUAL_STORAGE_TYPE.assert_called_once_with()
            mock_get_virtual_storage_type_vendor.assert_called_once_with()
            self.assertEqual(
                self._vdisk_class.VIRTUAL_STORAGE_TYPE_DEVICE_ISO,
                mock_Win32_VIRTUAL_STORAGE_TYPE.return_value.DeviceId)
            self.assertEqual(self._ctypes_mock.wintypes.HANDLE.return_value,
                             self._vdisk_class._handle)

    def test_open(self):
        self._test_open(handle=None, ret_val=None)

    def test_open_exception(self):
        self._test_open(handle=None, ret_val=100)

    def test_open_handle_exists(self):
        self._test_open(handle=None, ret_val=None)

    def _test_attach(self, ret_val):
        virtdisk = self._ctypes_mock.windll.virtdisk
        self.virtual_disk.virtdisk = virtdisk
        virtdisk.AttachVirtualDisk.return_value = ret_val

        if ret_val:
            with self.assert_raises_windows_message(
                    "Cannot attach virtual disk: %r",
                    ret_val):
                self._vdisk_class.attach()
        else:
            self._vdisk_class.attach()

        virtdisk.AttachVirtualDisk.assert_called_once_with(
            self._vdisk_class._handle, 0,
            self._vdisk_class.ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY, 0, 0, 0)

    def test_attach(self):
        self._test_attach(ret_val=None)

    def test_attach_exception(self):
        self._test_attach(ret_val=100)

    def _test_detach(self, ret_val):
        virtdisk = self._ctypes_mock.windll.virtdisk
        self.virtual_disk.virtdisk = virtdisk
        virtdisk.DetachVirtualDisk.return_value = ret_val

        if ret_val:
            with self.assert_raises_windows_message(
                    "Cannot detach virtual disk: %r", ret_val):
                self._vdisk_class.detach()
        else:
            self._vdisk_class.detach()

        virtdisk.DetachVirtualDisk.assert_called_once_with(
            self._vdisk_class._handle,
            self._vdisk_class.DETACH_VIRTUAL_DISK_FLAG_NONE, 0)

    def test_detach(self):
        self._test_detach(ret_val=None)

    def test_detach_exception(self):
        self._test_detach(ret_val=100)

    def _test_get_physical_path(self, ret_val):
        virtdisk = self._ctypes_mock.windll.virtdisk
        self.virtual_disk.virtdisk = virtdisk
        virtdisk.GetVirtualDiskPhysicalPath.return_value = ret_val

        buf = self._ctypes_mock.create_unicode_buffer.return_value

        if ret_val:
            with self.assert_raises_windows_message(
                    "Cannot get virtual disk physical path: %r", ret_val):
                self._vdisk_class.get_physical_path()
        else:
            response = self._vdisk_class.get_physical_path()
            self.assertEqual(buf.value, response)

        self._ctypes_mock.create_unicode_buffer.assert_called_once_with(1024)
        self._ctypes_mock.wintypes.DWORD.assert_called_once_with(
            self._ctypes_mock.sizeof.return_value)
        self._ctypes_mock.sizeof.assert_called_once_with(
            buf)

        virtdisk.GetVirtualDiskPhysicalPath.assert_called_once_with(
            self._vdisk_class._handle,
            self._ctypes_mock.byref.return_value,
            self._ctypes_mock.create_unicode_buffer.return_value)
        self._ctypes_mock.byref.assert_called_once_with(
            self._ctypes_mock.wintypes.DWORD.return_value)
        self._ctypes_mock.create_unicode_buffer.assert_called_once_with(1024)

    def test_get_physical_path(self):
        self._test_get_physical_path(ret_val=None)

    def test_get_physical_path_fails(self):
        self._test_get_physical_path(ret_val=100)

    @mock.patch('cloudbaseinit.utils.windows.virtual_disk'
                '.VirtualDisk.get_physical_path')
    def _test_get_cdrom_drive_mount_point(self, mock_get_physical_path,
                                          buf_len, ret_val, last_error=None):
        buf = self._ctypes_mock.create_unicode_buffer.return_value
        kernel32 = self.virtual_disk.kernel32
        kernel32.GetLogicalDriveStringsW.return_value = buf_len
        kernel32.QueryDosDeviceW.return_value = ret_val
        self._ctypes_mock.wstring_at.return_value = [mock.sentinel.value1,
                                                     mock.sentinel.value2]
        dev = self._ctypes_mock.create_unicode_buffer.return_value
        dev.value = mock_get_physical_path.return_value
        self._ctypes_mock.sizeof.return_value = 1

        expected_sizeof = [mock.call(buf),
                           mock.call(self._ctypes_mock.wintypes.WCHAR)]
        expected_create_unicode_buffer = [mock.call(2048)]

        if not buf_len:
            with self.assert_raises_windows_message(
                    "Cannot enumerate logical devices: %r", last_error):
                self._vdisk_class.get_cdrom_drive_mount_point()
        elif not ret_val:
            with self.assert_raises_windows_message(
                    "Cannot query NT device: %r", last_error):
                self._vdisk_class.get_cdrom_drive_mount_point()

            expected_create_unicode_buffer.append(mock.call(2048))
            expected_sizeof.append(mock.call(self._ctypes_mock.wintypes.WCHAR))
            expected_sizeof.append(
                mock.call(
                    self._ctypes_mock.create_unicode_buffer.return_value))
            expected_sizeof.append(mock.call(self._ctypes_mock.wintypes.WCHAR))

        else:
            response = self._vdisk_class.get_cdrom_drive_mount_point()

            mock_get_physical_path.assert_called_once_with()
            self._ctypes_mock.wstring_at.assert_called_once_with(
                self._ctypes_mock.addressof.return_value + 0 * 1)

            self._ctypes_mock.addressof.assert_called_once_with(buf)
            kernel32.QueryDosDeviceW.assert_called_once_with(
                [mock.sentinel.value1],
                self._ctypes_mock.create_unicode_buffer.return_value, 1)

            expected_sizeof.append(mock.call(self._ctypes_mock.wintypes.WCHAR))
            expected_sizeof.append(
                mock.call(
                    self._ctypes_mock.create_unicode_buffer.return_value))
            expected_sizeof.append(mock.call(self._ctypes_mock.wintypes.WCHAR))
            expected_create_unicode_buffer.append(mock.call(2048))

            self.assertEqual(self._ctypes_mock.wstring_at.return_value[:-1],
                             response)

        self.assertEqual(
            expected_create_unicode_buffer,
            self._ctypes_mock.create_unicode_buffer.call_args_list)
        self.assertEqual(expected_sizeof,
                         self._ctypes_mock.sizeof.call_args_list)

        kernel32.GetLogicalDriveStringsW.assert_called_once_with(1, buf)

    def test_get_cdrom_drive_mount_point_exception_buf_len(self):
        self._test_get_cdrom_drive_mount_point(buf_len=0, ret_val=1,
                                               last_error=100)

    def test_get_cdrom_drive_mount_point_exception_query(self):
        self._test_get_cdrom_drive_mount_point(buf_len=1, ret_val=0,
                                               last_error=100)

    def test_get_cdrom_drive_mount_point(self):
        self._test_get_cdrom_drive_mount_point(buf_len=1, ret_val=1)

    def test_close(self):
        self._vdisk_class.close()

        self.virtual_disk.kernel32.CloseHandle.assert_called_once_with(
            self._vdisk_class._handle)
        self.assertEqual(0, self._vdisk_class._handle)
