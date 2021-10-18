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

import comtypes
import ctypes
import re

from oslo_log import log as oslo_logging

from cloudbaseinit.utils.windows.storage import base
from cloudbaseinit.utils.windows import vds

LOG = oslo_logging.getLogger(__name__)

VDS_E_EXTENT_SIZE_LESS_THAN_MIN = -2147212237

ole32 = ctypes.windll.ole32
ole32.CoTaskMemFree.restype = None
ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]


def _enumerate(query):
    """Enumerate VDS service queries."""
    while True:
        unk, avail = query.Next(1)
        if not avail:
            return
        yield unk


class VDSStorageManager(base.BaseStorageManager):

    def __init__(self, *args, **kwargs):
        super(VDSStorageManager, self).__init__(*args, **kwargs)
        self._vds_service = None

    def _get_vds_service(self):
        if not self._vds_service:
            self._vds_service = vds.load_vds_service()
        return self._vds_service

    def _extend_volumes(self, pack, volume_indexes):
        for unk in _enumerate(pack.QueryVolumes()):
            volume = unk.QueryInterface(vds.IVdsVolume)
            volume_prop = volume.GetProperties()
            try:
                extend_volume = True
                if volume_indexes:
                    volume_name = ctypes.wstring_at(volume_prop.pwszName)
                    volume_idx = self._get_volume_index(volume_name)
                    if volume_idx not in volume_indexes:
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

            try:
                input_disks_ar = (vds.VDS_INPUT_DISK *
                                  len(input_disks))(*input_disks)
                extend_job = volume.Extend(input_disks_ar, len(input_disks))
                extend_job.Wait()
            except comtypes.COMError as ex:
                if ex.hresult == VDS_E_EXTENT_SIZE_LESS_THAN_MIN:
                    LOG.debug(
                        'Volume extension failed because of a '
                        'Windows disk management bug issue where the '
                        'estimated extend size is less than the minimum.')
                else:
                    raise

    def _get_volume_extents_to_resize(self, pack, volume_id):
        volume_extents = []

        for unk in _enumerate(pack.QueryDisks()):
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
        return [unk.QueryInterface(vds.IVdsSwProvider)
                for unk in _enumerate(
                    svc.QueryProviders(vds.VDS_QUERY_SOFTWARE_PROVIDERS))]

    def _query_packs(self, provider):
        return [unk.QueryInterface(vds.IVdsPack)
                for unk in _enumerate(provider.QueryPacks())]

    def extend_volumes(self, volume_indexes=None):
        svc = self._get_vds_service()
        providers = self._query_providers(svc)

        for provider in providers:
            packs = self._query_packs(provider)
            for pack in packs:
                self._extend_volumes(pack, volume_indexes)

    def get_san_policy(self):
        svc = self._get_vds_service()
        svc_san = svc.QueryInterface(vds.IVdsServiceSAN)
        return svc_san.GetSANPolicy()

    def set_san_policy(self, san_policy):
        svc = self._get_vds_service()
        svc_san = svc.QueryInterface(vds.IVdsServiceSAN)
        svc_san.SetSANPolicy(san_policy)
