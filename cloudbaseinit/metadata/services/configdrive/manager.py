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
import sys
import tempfile
import uuid
import wmi

from ctypes import wintypes

from cloudbaseinit.openstack.common import log as logging

from windows.disk.physical_disk import *
from windows.disk.virtual_disk import *

LOG = logging.getLogger(__name__)


class ConfigDriveManager(object):
    def _get_physical_disks_path(self):
        l = []
        conn = wmi.WMI(moniker='//./root/cimv2')
        q = conn.query('SELECT DeviceID FROM Win32_DiskDrive')
        for r in q:
           l.append(r.DeviceID)
        return l

    def _get_config_drive_cdrom_mount_point(self):
        conn = wmi.WMI(moniker='//./root/cimv2')
        q = conn.query('SELECT Drive FROM Win32_CDROMDrive WHERE MediaLoaded = True')
        for r in q:
            drive = r.Drive + '\\'
            q1 = conn.query('SELECT Label FROM Win32_Volume WHERE Name = \'%(drive)s\'' % locals())
            for r1 in q1:
                if r1.Label == "config-2" and \
                    os.path.exists(os.path.join(drive, 'openstack\\latest\\meta_data.json')):
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

        if geom.MediaType != Win32_DiskGeometry.FixedMedia:
            return None

        disk_size = geom.Cylinders * geom.TracksPerCylinder * \
            geom.SectorsPerTrack * geom.BytesPerSector

        boot_record_off = 0x8000;
        id_off = 1;
        volume_size_off = 80;
        block_size_off = 128;
        iso_id = 'CD001'

        offset = boot_record_off / geom.BytesPerSector * geom.BytesPerSector
        bytes_to_read = geom.BytesPerSector

        if disk_size <= offset + bytes_to_read:
            return None

        phys_disk.seek(offset)
        (buf, bytes_read) = phys_disk.read(bytes_to_read)

        buf_off = boot_record_off - offset + id_off
        if iso_id != buf[buf_off : buf_off + len(iso_id)]:
            return None

        buf_off = boot_record_off - offset + volume_size_off
        num_blocks = self._c_char_array_to_c_ushort(buf, buf_off)

        buf_off = boot_record_off - offset + block_size_off
        block_size = self._c_char_array_to_c_ushort(buf, buf_off)

        return num_blocks * block_size

    def _write_iso_file(self, phys_disk, path, iso_file_size):
        with open(path, 'wb') as f:
            geom = phys_disk.get_geometry()
            disk_size = geom.Cylinders * geom.TracksPerCylinder * \
                geom.SectorsPerTrack * geom.BytesPerSector

            offset = 0
            # Get a multiple of the sector byte size
            bytes_to_read = 4096 / geom.BytesPerSector * geom.BytesPerSector

            while offset < iso_file_size:
                phys_disk.seek(offset)
                bytes_to_read = min(bytes_to_read, iso_file_size - offset)
                (buf, bytes_read) = phys_disk.read(bytes_to_read)
                f.write(buf)
                offset += bytes_read

    def _copy_iso_files(self, iso_file_path, target_path):
        virt_disk = VirtualDisk(iso_file_path)
        virt_disk.open()
        try:
            virt_disk.attach()
            cdrom_mount_point = virt_disk.get_cdrom_drive_mount_point()
            shutil.copytree(cdrom_mount_point, target_path)
        finally:
            try:
                virt_disk.detach()
            except:
                pass
            virt_disk.close()

    def _extract_iso_disk_file(self, iso_file_path):
        iso_disk_found = False
        for path in self._get_physical_disks_path():
            phys_disk = PhysicalDisk(path)
            try:
                phys_disk.open()
                iso_file_size = self._get_iso_disk_size(phys_disk)
                if iso_file_size:
                    self._write_iso_file(phys_disk, iso_file_path,
                        iso_file_size)
                    iso_disk_found = True
                    break
            except:
                # Ignore exception
                pass
            finally:
                phys_disk.close()
        return iso_disk_found

    def _os_supports_iso_virtual_disks(self):
        # Feature supported starting from Windows 8 / 2012
        ver = sys.getwindowsversion();
        supported = (ver[0] >= 6 and ver[1] >= 2)
        if not supported:
            LOG.debug('ISO virtual disks are not supported on '
                'this version of Windows')
        return supported

    def get_config_drive_files(self, target_path, check_raw_hhd=True, check_cdrom=True):
        config_drive_found = False
        if check_raw_hhd and self._os_supports_iso_virtual_disks():
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
            if self._extract_iso_disk_file(iso_file_path):
                self._copy_iso_files(iso_file_path, target_path)
                config_drive_found = True
        finally:
            if os.path.exists(iso_file_path):
                os.remove(iso_file_path)
        return config_drive_found

