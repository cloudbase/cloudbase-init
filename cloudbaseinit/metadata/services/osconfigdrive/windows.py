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


import itertools
import os
import shutil
import struct
import tempfile
import uuid

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services.osconfigdrive import base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils.windows import disk
from cloudbaseinit.utils.windows import vfat

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

MAX_SECTOR_SIZE = 4096
# Absolute offset values and the ISO magic string.
OFFSET_BOOT_RECORD = 0x8000
OFFSET_ISO_ID = OFFSET_BOOT_RECORD + 1
ISO_ID = b'CD001'
# Little-endian unsigned short size values.
OFFSET_VOLUME_SIZE = OFFSET_BOOT_RECORD + 80
OFFSET_BLOCK_SIZE = OFFSET_BOOT_RECORD + 128
PEEK_SIZE = 2


class WindowsConfigDriveManager(base.BaseConfigDriveManager):

    def __init__(self):
        super(WindowsConfigDriveManager, self).__init__()
        self._osutils = osutils_factory.get_os_utils()

    def _meta_data_file_exists(self, drive, metadata_file):
        metadata_file = os.path.join(drive, metadata_file)

        if os.path.exists(metadata_file):
            return True

        LOG.debug('%s not found', metadata_file)
        return False

    def _check_for_config_drive(self, drive, required_drive_label,
                                metadata_file):
        label = self._osutils.get_volume_label(drive)
        if label and label.lower() == required_drive_label and \
                self._meta_data_file_exists(drive, metadata_file):
            LOG.info('Config Drive found on %s', drive)
            return True
        LOG.debug("Looking for a Config Drive with label '%s' on '%s'. "
                  "Found mismatching label '%s'.",
                  required_drive_label, drive, label)
        return False

    def _get_iso_file_size(self, device):
        if not device.fixed:
            return None

        if not device.size > (OFFSET_BLOCK_SIZE + PEEK_SIZE):
            return None

        off = device.seek(OFFSET_ISO_ID)
        magic = device.read(len(ISO_ID), skip=OFFSET_ISO_ID - off)
        if ISO_ID != magic:
            return None

        off = device.seek(OFFSET_VOLUME_SIZE)
        volume_size_bytes = device.read(PEEK_SIZE,
                                        skip=OFFSET_VOLUME_SIZE - off)
        off = device.seek(OFFSET_BLOCK_SIZE)
        block_size_bytes = device.read(PEEK_SIZE,
                                       skip=OFFSET_BLOCK_SIZE - off)
        volume_size = struct.unpack("<H", volume_size_bytes)[0]
        block_size = struct.unpack("<H", block_size_bytes)[0]

        return volume_size * block_size

    def _write_iso_file(self, device, iso_file_path, iso_file_size):
        with open(iso_file_path, 'wb') as stream:
            offset = 0
            # Read multiples of the sector size bytes
            # until the entire ISO content is written.
            while offset < iso_file_size:
                real_offset = device.seek(offset)
                bytes_to_read = min(MAX_SECTOR_SIZE, iso_file_size - offset)
                data = device.read(bytes_to_read, skip=offset - real_offset)
                stream.write(data)
                offset += bytes_to_read

    def _extract_files_from_iso(self, iso_file_path):
        bsdtar_args = [CONF.bsdtar_path, '-xf', iso_file_path,
                       '-C', self.target_path]

        if not os.path.exists(CONF.bsdtar_path):
            raise exception.CloudbaseInitException(
                'Bsdtar path "%s" does not exist.' % CONF.bsdtar_path)

        (out, err, exit_code) = self._osutils.execute_process(bsdtar_args,
                                                              False)

        if exit_code:
            raise exception.CloudbaseInitException(
                'Failed to execute "bsdtar" from path "%(bsdtar_path)s" with '
                'exit code: %(exit_code)s\n%(out)s\n%(err)s' % {
                    'bsdtar_path': CONF.bsdtar_path,
                    'exit_code': exit_code,
                    'out': out, 'err': err})

    def _extract_iso_from_devices(self, devices):
        """Search across multiple devices for a raw ISO."""
        extracted = False
        iso_file_path = os.path.join(tempfile.gettempdir(),
                                     str(uuid.uuid4()) + '.iso')

        for device in devices:
            try:
                with device:
                    iso_file_size = self._get_iso_file_size(device)
                    if iso_file_size:
                        LOG.info('ISO9660 disk found on %s', device)
                        self._write_iso_file(device, iso_file_path,
                                             iso_file_size)
                        self._extract_files_from_iso(iso_file_path)
                        extracted = True
                        break
            except Exception as exc:
                LOG.warning('ISO extraction failed on %(device)s with '
                            '%(error)r', {"device": device, "error": exc})

        if os.path.isfile(iso_file_path):
            os.remove(iso_file_path)
        return extracted

    def _get_config_drive_from_cdrom_drive(self, drive_label, metadata_file):
        for drive_letter in self._osutils.get_cdrom_drives():
            if self._check_for_config_drive(drive_letter, drive_label,
                                            metadata_file):
                os.rmdir(self.target_path)
                shutil.copytree(drive_letter, self.target_path)
                return True

        return False

    def _get_config_drive_from_raw_hdd(self, drive_label, metadata_file):
        disks = map(disk.Disk, self._osutils.get_physical_disks())
        return self._extract_iso_from_devices(disks)

    def _get_config_drive_from_vfat(self, drive_label, metadata_file):
        for drive_path in self._osutils.get_physical_disks():
            if vfat.is_vfat_drive(self._osutils, drive_path):
                LOG.info('Config Drive found on disk %r', drive_path)
                vfat.copy_from_vfat_drive(self._osutils, drive_path,
                                          self.target_path)
                return True
        return False

    def _get_config_drive_from_partition(self, drive_label, metadata_file):
        for disk_path in self._osutils.get_physical_disks():
            physical_drive = disk.Disk(disk_path)
            with physical_drive:
                partitions = physical_drive.partitions()
            extracted = self._extract_iso_from_devices(partitions)
            if extracted:
                return True
        return False

    def _get_config_drive_from_volume(self, drive_label, metadata_file):
        """Look through all the volumes for config drive."""
        volumes = self._osutils.get_volumes()
        for volume in volumes:
            if self._check_for_config_drive(volume, drive_label,
                                            metadata_file):
                os.rmdir(self.target_path)
                shutil.copytree(volume, self.target_path)
                return True
        return False

    def _get_config_drive_files(self, drive_label, metadata_file,
                                cd_type, cd_location):
        try:
            get_config_drive = self.config_drive_type_location.get(
                "{}_{}".format(cd_location, cd_type))
            if get_config_drive:
                return get_config_drive(drive_label, metadata_file)
            else:
                LOG.debug("Irrelevant type %(type)s in %(location)s "
                          "location; skip",
                          {"type": cd_type, "location": cd_location})
        except Exception as exc:
            LOG.warning("Config type %(type)s not found in %(loc)s "
                        "location; Error: '%(err)r'",
                        {"type": cd_type, "loc": cd_location, "err": exc})

        return False

    def get_config_drive_files(self, drive_label, metadata_file,
                               searched_types=None, searched_locations=None):
        searched_types = searched_types or []
        searched_locations = searched_locations or []

        for cd_type, cd_location in itertools.product(searched_types,
                                                      searched_locations):
            LOG.debug('Looking for Config Drive %(type)s in %(location)s '
                      'with expected label %(drive_label)s',
                      {"type": cd_type, "location": cd_location,
                       "drive_label": drive_label})
            if self._get_config_drive_files(drive_label, metadata_file,
                                            cd_type, cd_location):
                return True

        return False

    @property
    def config_drive_type_location(self):
        return {
            "cdrom_iso": self._get_config_drive_from_cdrom_drive,
            "hdd_iso": self._get_config_drive_from_raw_hdd,
            "hdd_vfat": self._get_config_drive_from_vfat,
            "partition_iso": self._get_config_drive_from_partition,
            "partition_vfat": self._get_config_drive_from_volume,
        }
