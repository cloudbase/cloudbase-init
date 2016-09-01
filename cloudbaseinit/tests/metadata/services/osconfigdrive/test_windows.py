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
import itertools
import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


CONF = cloudbaseinit_conf.CONF

OPEN = mock.mock_open()


class TestWindowsConfigDriveManager(unittest.TestCase):

    def setUp(self):
        module_path = "cloudbaseinit.metadata.services.osconfigdrive.windows"
        mock_ctypes = mock.MagicMock()
        mock_ctypes.wintypes = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'disk': mock.Mock(),
             'ctypes': mock_ctypes,
             'winioctlcon': mock.Mock()})
        self._module_patcher.start()
        self.addCleanup(self._module_patcher.stop)
        self.conf_module = importlib.import_module(module_path)

        self.conf_module.osutils_factory = mock.Mock()
        self.conf_module.disk.Disk = mock.MagicMock()
        self.conf_module.tempfile = mock.Mock()
        self.mock_gettempdir = self.conf_module.tempfile.gettempdir
        self.mock_gettempdir.return_value = "tempdir"
        self.conf_module.uuid = mock.Mock()
        self.mock_uuid4 = self.conf_module.uuid.uuid4
        self.mock_uuid4.return_value = "uuid"
        self._config_manager = self.conf_module.WindowsConfigDriveManager()
        self.addCleanup(os.rmdir, self._config_manager.target_path)
        self.osutils = mock.Mock()
        self._config_manager._osutils = self.osutils
        self.snatcher = testutils.LogSnatcher(module_path)

    @mock.patch('os.path.exists')
    def _test_check_for_config_drive(self, mock_exists, exists=True,
                                     label="config-2", fail=False):
        drive = "C:\\"
        self.osutils.get_volume_label.return_value = label
        mock_exists.return_value = exists

        with self.snatcher:
            response = self._config_manager._check_for_config_drive(drive)

        self.osutils.get_volume_label.assert_called_once_with(drive)
        if exists and not fail:
            self.assertEqual(["Config Drive found on C:\\"],
                             self.snatcher.output)
        self.assertEqual(not fail, response)

    def test_check_for_config_drive_exists(self):
        self._test_check_for_config_drive()

    def test_check_for_config_drive_exists_upper_label(self):
        self._test_check_for_config_drive(label="CONFIG-2")

    def test_check_for_config_drive_missing(self):
        self._test_check_for_config_drive(exists=False, fail=True)

    def test_check_for_config_drive_wrong_label(self):
        self._test_check_for_config_drive(label="config-3", fail=True)

    def _test_get_iso_file_size(self, fixed=True, small=False,
                                found_iso=True):
        device = mock.Mock()
        device.fixed = fixed
        device.size = (self.conf_module.OFFSET_BLOCK_SIZE +
                       self.conf_module.PEEK_SIZE + int(not small))
        iso_id = self.conf_module.ISO_ID
        if not found_iso:
            iso_id = b"pwned"
        iso_off = self.conf_module.OFFSET_ISO_ID - 1
        volume_off = self.conf_module.OFFSET_VOLUME_SIZE - 1
        block_off = self.conf_module.OFFSET_BLOCK_SIZE - 1
        volume_bytes = b'd\x00'      # 100
        block_bytes = b'\x00\x02'    # 512
        device.seek.side_effect = [iso_off, volume_off, block_off]
        device.read.side_effect = [iso_id, volume_bytes, block_bytes]

        response = self._config_manager._get_iso_file_size(device)
        if not fixed or small or not found_iso:
            self.assertIsNone(response)
            return

        seek_calls = [
            mock.call(self.conf_module.OFFSET_ISO_ID),
            mock.call(self.conf_module.OFFSET_VOLUME_SIZE),
            mock.call(self.conf_module.OFFSET_BLOCK_SIZE)]
        read_calls = [
            mock.call(len(iso_id),
                      skip=self.conf_module.OFFSET_ISO_ID - iso_off),
            mock.call(self.conf_module.PEEK_SIZE,
                      skip=self.conf_module.OFFSET_VOLUME_SIZE - volume_off),
            mock.call(self.conf_module.PEEK_SIZE,
                      skip=self.conf_module.OFFSET_BLOCK_SIZE - block_off)]
        device.seek.assert_has_calls(seek_calls)
        device.read.assert_has_calls(read_calls)
        self.assertEqual(100 * 512, response)

    def test_get_iso_file_size_not_fixed(self):
        self._test_get_iso_file_size(fixed=False)

    def test_get_iso_file_size_small(self):
        self._test_get_iso_file_size(small=True)

    def test_get_iso_file_size_not_found(self):
        self._test_get_iso_file_size(found_iso=False)

    def test_get_iso_file_size(self):
        self._test_get_iso_file_size()

    @mock.patch("six.moves.builtins.open", new=OPEN)
    def test_write_iso_file(self):
        file_path = "fake\\path"
        file_size = 100 * 512
        sector_size = self.conf_module.MAX_SECTOR_SIZE
        offsets = list(range(0, file_size, sector_size))
        remain = file_size % sector_size
        reads = ([b"\x00" * sector_size] *
                 (len(offsets) - int(bool(remain))) +
                 ([b"\x00" * remain] if remain else []))

        device = mock.Mock()
        device_seek_calls = [mock.call(off) for off in offsets]
        device_read_calls = [
            mock.call(min(sector_size, file_size - off), skip=0)
            for off in offsets]
        stream_write_calls = [mock.call(read) for read in reads]
        device.seek.side_effect = offsets
        device.read.side_effect = reads

        self._config_manager._write_iso_file(device, file_path, file_size)
        device.seek.assert_has_calls(device_seek_calls)
        device.read.assert_has_calls(device_read_calls)
        OPEN.return_value.write.assert_has_calls(stream_write_calls)

    def _test_extract_files_from_iso(self, exit_code):
        fake_path = os.path.join('fake', 'path')
        fake_target_path = os.path.join(fake_path, 'target')
        self._config_manager.target_path = fake_target_path
        args = [CONF.bsdtar_path, '-xf', fake_path, '-C', fake_target_path]

        self.osutils.execute_process.return_value = ('fake out', 'fake err',
                                                     exit_code)
        if exit_code:
            self.assertRaises(exception.CloudbaseInitException,
                              self._config_manager._extract_files_from_iso,
                              fake_path)
        else:
            self._config_manager._extract_files_from_iso(fake_path)

        self.osutils.execute_process.assert_called_once_with(args, False)

    def test_extract_files_from_iso(self):
        self._test_extract_files_from_iso(exit_code=0)

    def test_extract_files_from_iso_fail(self):
        self._test_extract_files_from_iso(exit_code=1)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager._extract_files_from_iso')
    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager._write_iso_file')
    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager._get_iso_file_size')
    def _test_extract_iso_from_devices(self, mock_get_iso_file_size,
                                       mock_write_iso_file,
                                       mock_extract_files_from_iso,
                                       found=True):
        # For every device (mock) in the list of available devices:
        #   first - skip (no size)
        #   second - error (throws Exception)
        #   third - extract (is ok)
        #   fourth - unreachable (already found ok device)
        size = 100 * 512
        devices = [mock.MagicMock() for _ in range(4)]
        devices[1].__enter__.side_effect = [Exception]
        rest = [size] if found else [None]
        mock_get_iso_file_size.side_effect = [None] + rest * 2
        file_path = os.path.join("tempdir", "uuid.iso")

        with self.snatcher:
            response = self._config_manager._extract_iso_from_devices(devices)
        self.mock_gettempdir.assert_called_once_with()
        mock_get_iso_file_size.assert_has_calls([
            mock.call(devices[0]), mock.call(devices[2])])
        expected_log = [
            "ISO extraction failed on %(device)s with %(error)r" %
            {"device": devices[1], "error": Exception()}]
        if found:
            mock_write_iso_file.assert_called_once_with(devices[2],
                                                        file_path, size)
            mock_extract_files_from_iso.assert_called_once_with(file_path)
            expected_log.append("ISO9660 disk found on %s" % devices[2])
        self.assertEqual(expected_log, self.snatcher.output)
        self.assertEqual(found, response)

    def test_extract_iso_from_devices_not_found(self):
        self._test_extract_iso_from_devices(found=False)

    def test_extract_iso_from_devices(self):
        self._test_extract_iso_from_devices()

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_check_for_config_drive')
    @mock.patch('shutil.copytree')
    @mock.patch('os.rmdir')
    def _test_get_config_drive_from_cdrom_drive(self, mock_os_rmdir,
                                                mock_copytree,
                                                mock_check_for_config_drive,
                                                found=True):
        drives = ["C:\\", "M:\\", "I:\\", "N:\\"]
        self.osutils.get_cdrom_drives.return_value = drives
        checks = [False, False, True, False]
        if not found:
            checks[2] = False
        mock_check_for_config_drive.side_effect = checks

        response = self._config_manager._get_config_drive_from_cdrom_drive()

        self.osutils.get_cdrom_drives.assert_called_once_with()
        idx = 3 if found else 4
        check_calls = [mock.call(drive) for drive in drives[:idx]]
        mock_check_for_config_drive.assert_has_calls(check_calls)
        if found:
            mock_os_rmdir.assert_called_once_with(
                self._config_manager.target_path)
            mock_copytree.assert_called_once_with(
                drives[2], self._config_manager.target_path)

        self.assertEqual(found, response)

    def test_get_config_drive_from_cdrom_drive_not_found(self):
        self._test_get_config_drive_from_cdrom_drive(found=False)

    def test_get_config_drive_from_cdrom_drive(self):
        self._test_get_config_drive_from_cdrom_drive()

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_extract_iso_from_devices')
    @mock.patch("six.moves.builtins.map")
    def test_get_config_drive_from_raw_hdd(self, mock_map,
                                           mock_extract_iso_from_devices):
        Disk = self.conf_module.disk.Disk
        paths = [mock.Mock() for _ in range(3)]
        self.osutils.get_physical_disks.return_value = paths
        mock_extract_iso_from_devices.return_value = True

        response = self._config_manager._get_config_drive_from_raw_hdd()
        mock_map.assert_called_once_with(Disk, paths)
        self.osutils.get_physical_disks.assert_called_once_with()
        mock_extract_iso_from_devices.assert_called_once_with(
            mock_map.return_value)
        self.assertTrue(response)

    @mock.patch('cloudbaseinit.utils.windows.vfat.copy_from_vfat_drive')
    @mock.patch('cloudbaseinit.utils.windows.vfat.is_vfat_drive')
    def test_get_config_drive_from_vfat(self, mock_is_vfat_drive,
                                        mock_copy_from_vfat_drive):
        self.osutils.get_physical_disks.return_value = (
            mock.sentinel.drive1,
            mock.sentinel.drive2,
        )
        mock_is_vfat_drive.side_effect = (None, True)

        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'osconfigdrive.windows') as snatcher:
            response = self._config_manager._get_config_drive_from_vfat()

        self.assertTrue(response)
        self.osutils.get_physical_disks.assert_called_once_with()

        expected_is_vfat_calls = [
            mock.call(self.osutils, mock.sentinel.drive1),
            mock.call(self.osutils, mock.sentinel.drive2),
        ]
        self.assertEqual(expected_is_vfat_calls, mock_is_vfat_drive.mock_calls)
        mock_copy_from_vfat_drive.assert_called_once_with(
            self.osutils,
            mock.sentinel.drive2,
            self._config_manager.target_path)

        expected_logging = [
            'Config Drive found on disk %r' % mock.sentinel.drive2,
        ]
        self.assertEqual(expected_logging, snatcher.output)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_extract_iso_from_devices')
    def _test_get_config_drive_from_partition(self,
                                              mock_extract_iso_from_devices,
                                              found=True):
        paths = [mock.Mock() for _ in range(3)]
        self.osutils.get_physical_disks.return_value = paths
        disks = list(map(self.conf_module.disk.Disk, paths))
        mock_extract_iso_from_devices.side_effect = [False, found, found]
        idx = 3 - int(found)
        extract_calls = [mock.call(disk.partitions())
                         for disk in disks[:idx]]

        response = self._config_manager._get_config_drive_from_partition()
        self.osutils.get_physical_disks.assert_called_once_with()
        mock_extract_iso_from_devices.assert_has_calls(extract_calls)
        self.assertEqual(found, response)

    def test_get_config_drive_from_partition_not_found(self):
        self._test_get_config_drive_from_partition(found=False)

    def test_get_config_drive_from_partition(self):
        self._test_get_config_drive_from_partition()

    @mock.patch('os.rmdir')
    @mock.patch('shutil.copytree')
    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_check_for_config_drive')
    def _test_get_config_drive_from_volume(self, mock_check_for_config_drive,
                                           mock_copytree, mock_os_rmdir,
                                           found=True):
        volumes = [mock.Mock() for _ in range(3)]
        self.osutils.get_volumes.return_value = volumes
        checks = [False, found, found]
        mock_check_for_config_drive.side_effect = checks
        idx = 3 - int(found)
        check_calls = [mock.call(volume) for volume in volumes[:idx]]

        response = self._config_manager._get_config_drive_from_volume()
        self.osutils.get_volumes.assert_called_once_with()
        mock_check_for_config_drive.assert_has_calls(check_calls)
        if found:
            mock_os_rmdir.assert_called_once_with(
                self._config_manager.target_path)
            mock_copytree.assert_called_once_with(
                volumes[1], self._config_manager.target_path)
        self.assertEqual(found, response)

    def test_get_config_drive_from_volume_not_found(self):
        self._test_get_config_drive_from_volume(found=False)

    def test_get_config_drive_from_volume(self):
        self._test_get_config_drive_from_volume()

    def _test__get_config_drive_files(self, cd_type, cd_location,
                                      func, found=True):
        response = self._config_manager._get_config_drive_files(cd_type,
                                                                cd_location)
        if found:
            if func:
                func.assert_called_once_with()
                self.assertEqual(func.return_value, response)
        else:
            self.assertFalse(response)

    def test__get_config_drive_files_not_found(self):
        self._test__get_config_drive_files(None, None, None, found=False)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_get_config_drive_from_cdrom_drive')
    def test__get_config_drive_files_cdrom_iso(self, func):
        self._test__get_config_drive_files(
            "iso", "cdrom", func)

    def test__get_config_drive_files_cdrom_vfat(self):
        self._test__get_config_drive_files(
            "vfat", "cdrom", None)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_get_config_drive_from_raw_hdd')
    def test__get_config_drive_files_hdd_iso(self, func):
        self._test__get_config_drive_files(
            "iso", "hdd", func)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_get_config_drive_from_vfat')
    def test__get_config_drive_files_hdd_vfat(self, func):
        self._test__get_config_drive_files(
            "vfat", "hdd", func)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_get_config_drive_from_partition')
    def test__get_config_drive_files_partition_iso(self, func):
        self._test__get_config_drive_files(
            "iso", "partition", func)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_get_config_drive_from_volume')
    def test__get_config_drive_files_partition_vfat(self, func):
        self._test__get_config_drive_files(
            "vfat", "partition", func)

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.windows.'
                'WindowsConfigDriveManager.'
                '_get_config_drive_files')
    def _test_get_config_drive_files(self, mock_get_config_drive_files,
                                     found=True):
        check_types = ["iso", "vfat"] if found else []
        check_locations = ["cdrom", "hdd", "partition"]
        product = list(itertools.product(check_types, check_locations))
        product_calls = [mock.call(cd_type, cd_location)
                         for cd_type, cd_location in product]
        mock_get_config_drive_files.side_effect = \
            [False] * (len(product_calls) - 1) + [True]
        expected_log = ["Looking for Config Drive %(type)s in %(location)s" %
                        {"type": cd_type, "location": cd_location}
                        for cd_type, cd_location in product]

        with self.snatcher:
            response = self._config_manager.get_config_drive_files(
                check_types, check_locations)
        mock_get_config_drive_files.assert_has_calls(product_calls)
        self.assertEqual(expected_log, self.snatcher.output)
        self.assertEqual(found, response)

    def test_get_config_drive_files_not_found(self):
        self._test_get_config_drive_files(found=False)

    def test_get_config_drive_files(self):
        self._test_get_config_drive_files()
