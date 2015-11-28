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

import wmi

from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.utils.windows.storage import base

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
