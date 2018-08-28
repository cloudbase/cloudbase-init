# Copyright 2013 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging
from six.moves import winreg

from cloudbaseinit import exception
from cloudbaseinit.utils.windows import kernel32
from cloudbaseinit.utils.windows.storage import base
from cloudbaseinit.utils.windows import wmi_loader

wmi = wmi_loader.wmi()

LOG = oslo_logging.getLogger(__name__)


class WSMStorageManager(base.BaseStorageManager):
    def __init__(self):
        self._conn = wmi.WMI(moniker='//./Root/Microsoft/Windows/Storage')

    def extend_volumes(self, volume_indexes=None):
        volumes = self._conn.MSFT_Volume()

        for idx, volume in enumerate(volumes, 1):
            # TODO(alexpilotti): don't rely on the volumes WMI query order
            if volume_indexes and idx not in volume_indexes:
                continue

            partitions = volume.associators(wmi_result_class='MSFT_Partition')
            for partition in partitions:
                (ret_val, _, size_max, _) = partition.GetSupportedSize()
                if ret_val:
                    raise exception.CloudbaseInitException(
                        "GetSupportedSize failed with error: %s" % ret_val)

                if int(size_max) > int(partition.Size):
                    LOG.info('Extending partition "%(partition_number)s" '
                             'to %(size)s bytes' %
                             {'partition_number': partition.PartitionNumber,
                              'size': size_max})
                    (ret_val, _) = partition.Resize(size_max)
                    if ret_val:
                        raise exception.CloudbaseInitException(
                            "Resize failed with error: %s" % ret_val)

    def get_san_policy(self):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            'SYSTEM\\CurrentControlSet\\Services\\partmgr\\'
                            'Parameters') as key:
            try:
                san_policy = winreg.QueryValueEx(key, 'SanPolicy')[0]
            except WindowsError as ex:
                if ex.winerror != 2:
                    raise
                san_policy = base.SAN_POLICY_OFFLINE_SHARED
            return san_policy

    def set_san_policy(self, san_policy):
        if san_policy != base.SAN_POLICY_ONLINE:
            raise exception.CloudbaseInitException(
                "Only SAN_POLICY_ONLINE is currently supported")
        handle = kernel32.CreateFileW(
            u"\\\\.\\PartmgrControl",
            kernel32.GENERIC_READ | kernel32.GENERIC_WRITE,
            kernel32.FILE_SHARE_READ | kernel32.FILE_SHARE_WRITE,
            None, kernel32.OPEN_EXISTING, 0, None)

        if handle == kernel32.INVALID_HANDLE_VALUE:
            raise exception.WindowsCloudbaseInitException(
                "Cannot access PartmgrControl: %r")

        try:
            input_data_online = ctypes.c_int64(0x100000008)
            input_data_size = 8
            control_code = 0x7C204

            if not kernel32.DeviceIoControl(
                    handle, control_code, ctypes.addressof(input_data_online),
                    input_data_size, None, 0, None, None):
                raise exception.WindowsCloudbaseInitException(
                    "DeviceIoControl failed: %r")
        finally:
            kernel32.CloseHandle(handle)
