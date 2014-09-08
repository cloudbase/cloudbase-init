# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 Cloudbase Solutions Srl
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
import re

from oslo.config import cfg

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.plugins import base
from cloudbaseinit.utils.windows import vds

ole32 = ctypes.windll.ole32
ole32.CoTaskMemFree.restype = None
ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]

opts = [
    cfg.ListOpt('volumes_to_extend',
                default=None,
                help='List of volumes that need to be extended '
                'if contiguous space is available on the disk. By default '
                'all the available volumes can be extended. Volumes must '
                'be specified using a comma separated list of volume indexes, '
                'e.g.: "1,2"'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class ExtendVolumesPlugin(base.BasePlugin):
    def _extend_volumes(self, pack, volume_idxs=None):
        enum = pack.QueryVolumes()
        while True:
            (unk, c) = enum.Next(1)
            if not c:
                break
            volume = unk.QueryInterface(vds.IVdsVolume)
            volume_prop = volume.GetProperties()
            try:
                extend_volume = True
                if volume_idxs is not None:
                    volume_name = ctypes.wstring_at(volume_prop.pwszName)
                    volume_idx = self._get_volume_index(volume_name)
                    if volume_idx not in volume_idxs:
                        extend_volume = False

                if extend_volume:
                    self._extend_volume(pack, volume, volume_prop)
            finally:
                ole32.CoTaskMemFree(volume_prop.pwszName)

    def _get_volume_index(self, volume_name):
        m = re.match(r"[^0-9]+([0-9]+)$", volume_name)
        if m:
            return int(m.group(1))

    def _extend_volume(self, pack, volume, volume_prop):
        volume_extents = self._get_volume_extents_to_resize(pack,
                                                            volume_prop.id)
        input_disks = []

        for (volume_extent, volume_extend_size) in volume_extents:
            input_disk = vds.VDS_INPUT_DISK()
            input_disks.append(input_disk)

            input_disk.diskId = volume_extent.diskId
            input_disk.memberIdx = volume_extent.memberIdx
            input_disk.plexId = volume_extent.plexId
            input_disk.ullSize = volume_extend_size

        if input_disks:
            extend_size = sum([i.ullSize for i in input_disks])
            volume_name = ctypes.wstring_at(volume_prop.pwszName)
            LOG.info('Extending volume "%s" with %s bytes' %
                     (volume_name, extend_size))

            input_disks_ar = (vds.VDS_INPUT_DISK *
                              len(input_disks))(*input_disks)
            async = volume.Extend(input_disks_ar, len(input_disks))
            async.Wait()

    def _get_volume_extents_to_resize(self, pack, volume_id):
        volume_extents = []

        enum = pack.QueryDisks()
        while True:
            (unk, c) = enum.Next(1)
            if not c:
                break
            disk = unk.QueryInterface(vds.IVdsDisk)

            (extents_p, num_extents) = disk.QueryExtents()
            try:
                extents_array_type = vds.VDS_DISK_EXTENT * num_extents
                extents_array = extents_array_type.from_address(
                    ctypes.addressof(extents_p.contents))

                volume_extent_extend_size = None

                for extent in extents_array:
                    if extent.volumeId == volume_id:
                        # Copy the extent in order to return it safely
                        # after the source is deallocated
                        extent_copy = vds.VDS_DISK_EXTENT()
                        ctypes.pointer(extent_copy)[0] = extent

                        volume_extent_extend_size = [extent_copy, 0]
                        volume_extents.append(volume_extent_extend_size)
                    elif (volume_extent_extend_size and
                          extent.type == vds.VDS_DET_FREE):
                        volume_extent_extend_size[1] += extent.ullSize
                    else:
                        volume_extent_extend_size = None
            finally:
                ole32.CoTaskMemFree(extents_p)

        # Return only the extents that need to be resized
        return [ve for ve in volume_extents if ve[1] > 0]

    def _query_providers(self, svc):
        providers = []
        enum = svc.QueryProviders(vds.VDS_QUERY_SOFTWARE_PROVIDERS)
        while True:
            (unk, c) = enum.Next(1)
            if not c:
                break
            providers.append(unk.QueryInterface(vds.IVdsSwProvider))
        return providers

    def _query_packs(self, provider):
        packs = []
        enum = provider.QueryPacks()
        while True:
            (unk, c) = enum.Next(1)
            if not c:
                break
            packs.append(unk.QueryInterface(vds.IVdsPack))
        return packs

    def _get_volumes_to_extend(self):
        if CONF.volumes_to_extend is not None:
            return list(map(int, CONF.volumes_to_extend))

    def execute(self, service, shared_data):
        svc = vds.load_vds_service()
        providers = self._query_providers(svc)

        volumes_to_extend = self._get_volumes_to_extend()

        for provider in providers:
            packs = self._query_packs(provider)
            for pack in packs:
                self._extend_volumes(pack, volumes_to_extend)

        return (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)

    def get_os_requirements(self):
        return ('win32', (5, 2))
