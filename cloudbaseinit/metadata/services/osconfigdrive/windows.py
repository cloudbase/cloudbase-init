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
import os
import shutil
import tempfile
import uuid

from ctypes import wintypes
from oslo.config import cfg

from cloudbaseinit import exception
from cloudbaseinit.metadata.services.osconfigdrive import base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils.windows import physical_disk

opts = [
    cfg.StrOpt('bsdtar_path', default='bsdtar.exe',
               help='Path to "bsdtar", used to extract ISO ConfigDrive '
                    'files'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class WindowsConfigDriveManager(base.BaseConfigDriveManager):

    def _get_config_drive_cdrom_mount_point(self):
        osutils = osutils_factory.get_os_utils()

        for drive in osutils.get_cdrom_drives():
            label = osutils.get_volume_label(drive)
            if label == "config-2" and \
                os.path.exists(os.path.join(drive,
                                            'openstack\\latest\\'
                                            'meta_data.json')):
                return drive
        return None

    def _c_char_array_to_c_ushort(self, buf, offset):
        low = ctypes.cast(buf[offset],
                          ctypes.POINTER(wintypes.WORD)).contents
        high = ctypes.cast(buf[offset + 1],
                           ctypes.POINTER(wintypes.WORD)).contents
        return (high.value << 8) + low.value

    def _get_iso_disk_size(self, phys_disk):
        geom = phys_disk.get_geometry()

        if geom.MediaType != physical_disk.Win32_DiskGeometry.FixedMedia:
            return None

        disk_size = geom.Cylinders * geom.TracksPerCylinder * \
            geom.SectorsPerTrack * geom.BytesPerSector

        boot_record_off = 0x8000
        id_off = 1
        volume_size_off = 80
        block_size_off = 128
        iso_id = 'CD001'

        offset = boot_record_off / geom.BytesPerSector * geom.BytesPerSector
        bytes_to_read = geom.BytesPerSector

        if disk_size <= offset + bytes_to_read:
            return None

        phys_disk.seek(offset)
        (buf, bytes_read) = phys_disk.read(bytes_to_read)

        buf_off = boot_record_off - offset + id_off
        if iso_id != buf[buf_off: buf_off + len(iso_id)]:
            return None

        buf_off = boot_record_off - offset + volume_size_off
        num_blocks = self._c_char_array_to_c_ushort(buf, buf_off)

        buf_off = boot_record_off - offset + block_size_off
        block_size = self._c_char_array_to_c_ushort(buf, buf_off)

        return num_blocks * block_size

    def _write_iso_file(self, phys_disk, path, iso_file_size):
        with open(path, 'wb') as f:
            geom = phys_disk.get_geometry()
            offset = 0
            # Get a multiple of the sector byte size
            bytes_to_read = 4096 / geom.BytesPerSector * geom.BytesPerSector

            while offset < iso_file_size:
                phys_disk.seek(offset)
                bytes_to_read = min(bytes_to_read, iso_file_size - offset)
                (buf, bytes_read) = phys_disk.read(bytes_to_read)
                f.write(buf)
                offset += bytes_read

    def _extract_iso_files(self, osutils, iso_file_path, target_path):
        os.makedirs(target_path)

        args = [CONF.bsdtar_path, '-xf', iso_file_path, '-C', target_path]
        (out, err, exit_code) = osutils.execute_process(args, False)

        if exit_code:
            raise exception.CloudbaseInitException(
                'Failed to execute "bsdtar" from path "%(bsdtar_path)s" with '
                'exit code: %(exit_code)s\n%(out)s\n%(err)s' % {
                    'bsdtar_path': CONF.bsdtar_path,
                    'exit_code': exit_code,
                    'out': out, 'err': err})

    def _extract_iso_disk_file(self, osutils, iso_file_path):
        iso_disk_found = False
        for path in osutils.get_physical_disks():
            phys_disk = physical_disk.PhysicalDisk(path)
            try:
                phys_disk.open()
                iso_file_size = self._get_iso_disk_size(phys_disk)
                if iso_file_size:
                    LOG.debug('ISO9660 disk found on raw HDD: %s' % path)
                    self._write_iso_file(phys_disk, iso_file_path,
                                         iso_file_size)
                    iso_disk_found = True
                    break
            except Exception:
                # Ignore exception
                pass
            finally:
                phys_disk.close()
        return iso_disk_found

    def get_config_drive_files(self, target_path, check_raw_hhd=True,
                               check_cdrom=True):
        config_drive_found = False
        if check_raw_hhd:
            LOG.debug('Looking for Config Drive in raw HDDs')
            config_drive_found = self._get_conf_drive_from_raw_hdd(
                target_path)

        if not config_drive_found and check_cdrom:
            LOG.debug('Looking for Config Drive in cdrom drives')
            config_drive_found = self._get_conf_drive_from_cdrom_drive(
                target_path)
        return config_drive_found

    def _get_conf_drive_from_cdrom_drive(self, target_path):
        cdrom_mount_point = self._get_config_drive_cdrom_mount_point()
        if cdrom_mount_point:
            shutil.copytree(cdrom_mount_point, target_path)
            return True
        return False

    def _get_conf_drive_from_raw_hdd(self, target_path):
        config_drive_found = False
        iso_file_path = os.path.join(tempfile.gettempdir(),
                                     str(uuid.uuid4()) + '.iso')
        try:
            osutils = osutils_factory.get_os_utils()

            if self._extract_iso_disk_file(osutils, iso_file_path):
                self._extract_iso_files(osutils, iso_file_path, target_path)
                config_drive_found = True
        finally:
            if os.path.exists(iso_file_path):
                os.remove(iso_file_path)
        return config_drive_found
