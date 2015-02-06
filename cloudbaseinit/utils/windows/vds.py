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

import comtypes
import ctypes

from comtypes import client
from ctypes import wintypes

VDS_QUERY_SOFTWARE_PROVIDERS = 1
VDS_DET_FREE = 1

CLSID_VdsLoader = '{9C38ED61-D565-4728-AEEE-C80952F0ECDE}'

msvcrt = ctypes.cdll.msvcrt
msvcrt.memcmp.restype = ctypes.c_int
msvcrt.memcmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]


class GUID(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.wintypes.DWORD),
        ("data2", ctypes.wintypes.WORD),
        ("data3", ctypes.wintypes.WORD),
        ("data4", ctypes.c_byte * 8)]

    def __eq__(self, other):
        if type(other) != GUID:
            return False
        return not msvcrt.memcmp(ctypes.addressof(self),
                                 ctypes.addressof(other),
                                 ctypes.sizeof(GUID))

    def __ne__(self, other):
        return not self.__eq__(other)


class VDS_DISK_PROP_SWITCH_TYPE(ctypes.Union):
    _fields_ = [
        ("dwSignature", wintypes.DWORD),
        ("DiskGuid", GUID),
    ]


class VDS_DISK_PROP(ctypes.Structure):
    _fields_ = [
        ("id", GUID),
        ("status", ctypes.c_int),
        ("ReserveMode", ctypes.c_int),
        ("health", ctypes.c_int),
        ("dwDeviceType", wintypes.DWORD),
        ("dwMediaType", wintypes.DWORD),
        ("ullSize", wintypes.ULARGE_INTEGER),
        ("ulBytesPerSector", wintypes.ULONG),
        ("ulSectorsPerTrack", wintypes.ULONG),
        ("ulTracksPerCylinder", wintypes.ULONG),
        ("ulFlags", wintypes.ULONG),
        ("BusType", ctypes.c_int),
        ("PartitionStyle", ctypes.c_int),
        ("switch_type", VDS_DISK_PROP_SWITCH_TYPE),
        ("pwszDiskAddress", ctypes.c_void_p),
        ("pwszName", ctypes.c_void_p),
        ("pwszFriendlyName", ctypes.c_void_p),
        ("pwszAdaptorName", ctypes.c_void_p),
        ("pwszDevicePath", ctypes.c_void_p),
    ]


class VDS_DISK_EXTENT(ctypes.Structure):
    _fields_ = [
        ("diskId", GUID),
        ("type", ctypes.c_int),
        ("ullOffset", wintypes.ULARGE_INTEGER),
        ("ullSize", wintypes.ULARGE_INTEGER),
        ("volumeId", GUID),
        ("plexId", GUID),
        ("memberIdx", wintypes.ULONG),
    ]


class VDS_VOLUME_PROP(ctypes.Structure):
    _fields_ = [
        ("id", GUID),
        ("type", ctypes.c_int),
        ("status", ctypes.c_int),
        ("health", ctypes.c_int),
        ("TransitionState", ctypes.c_int),
        ("ullSize", wintypes.ULARGE_INTEGER),
        ("ulFlags", wintypes.ULONG),
        ("RecommendedFileSystemType", ctypes.c_int),
        ("pwszName", ctypes.c_void_p),
    ]


class VDS_INPUT_DISK(ctypes.Structure):
    _fields_ = [
        ("diskId", GUID),
        ("ullSize", wintypes.ULARGE_INTEGER),
        ("plexId", GUID),
        ("memberIdx", wintypes.ULONG),
    ]


class VDS_ASYNC_OUTPUT_cp(ctypes.Structure):
    _fields_ = [
        ("ullOffset", wintypes.ULARGE_INTEGER),
        ("volumeId", GUID),
    ]


class VDS_ASYNC_OUTPUT_cv(ctypes.Structure):
    _fields_ = [
        ("pVolumeUnk", wintypes.ULARGE_INTEGER),
    ]


class VDS_ASYNC_OUTPUT_bvp(ctypes.Structure):
    _fields_ = [
        ("pVolumeUnk", ctypes.POINTER(comtypes.IUnknown)),
    ]


class VDS_ASYNC_OUTPUT_sv(ctypes.Structure):
    _fields_ = [
        ("ullReclaimedBytes", wintypes.ULARGE_INTEGER),
    ]


class VDS_ASYNC_OUTPUT_cl(ctypes.Structure):
    _fields_ = [
        ("pLunUnk", ctypes.POINTER(comtypes.IUnknown)),
    ]


class VDS_ASYNC_OUTPUT_ct(ctypes.Structure):
    _fields_ = [
        ("pTargetUnk", ctypes.POINTER(comtypes.IUnknown)),
    ]


class VDS_ASYNC_OUTPUT_cpg(ctypes.Structure):
    _fields_ = [
        ("pPortalGroupUnk", ctypes.POINTER(comtypes.IUnknown)),
    ]


class VDS_ASYNC_OUTPUT_SWITCH_TYPE(ctypes.Union):
    _fields_ = [
        ("cp", VDS_ASYNC_OUTPUT_cp),
        ("cv", VDS_ASYNC_OUTPUT_cv),
        ("bvp", VDS_ASYNC_OUTPUT_bvp),
        ("sv", VDS_ASYNC_OUTPUT_sv),
        ("cl", VDS_ASYNC_OUTPUT_cl),
        ("ct", VDS_ASYNC_OUTPUT_ct),
        ("cpg", VDS_ASYNC_OUTPUT_cpg),
    ]


class VDS_ASYNC_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("switch_type", VDS_ASYNC_OUTPUT_SWITCH_TYPE),
    ]


class IEnumVdsObject(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{118610b7-8d94-4030-b5b8-500889788e4e}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'Next',
                           (['in'], wintypes.ULONG, 'celt'),
                           (['out'], ctypes.POINTER(ctypes.POINTER(
                                                    comtypes.IUnknown)),
                            'ppObjectArray'),
                           (['out'], ctypes.POINTER(wintypes.ULONG),
                            'pcFetched')),
    ]


class IVdsService(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{0818a8ef-9ba9-40d8-a6f9-e22833cc771e}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'IsServiceReady'),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'WaitForServiceReady'),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetProperties',
                           (['out'], ctypes.c_void_p, 'pServiceProp')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'QueryProviders',
                           (['in'], wintypes.DWORD, 'masks'),
                           (['out'],
                            ctypes.POINTER(ctypes.POINTER(IEnumVdsObject)),
                            'ppEnum'))
    ]


class IVdsServiceLoader(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{e0393303-90d4-4a97-ab71-e9b671ee2729}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'LoadService',
                           (['in'], wintypes.LPCWSTR, 'pwszMachineName'),
                           (['out'],
                            ctypes.POINTER(ctypes.POINTER(IVdsService)),
                            'ppService'))
    ]


class IVdsSwProvider(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{9aa58360-ce33-4f92-b658-ed24b14425b8}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'QueryPacks',
                           (['out'],
                            ctypes.POINTER(ctypes.POINTER(IEnumVdsObject)),
                            'ppEnum'))
    ]


class IVdsPack(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{3b69d7f5-9d94-4648-91ca-79939ba263bf}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetProperties',
                           (['out'], ctypes.c_void_p, 'pPackProp')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetProvider',
                           (['out'],
                            ctypes.POINTER(ctypes.POINTER(comtypes.IUnknown)),
                            'ppProvider')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'QueryVolumes',
                           (['out'],
                            ctypes.POINTER(ctypes.POINTER(IEnumVdsObject)),
                            'ppEnum')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'QueryDisks',
                           (['out'],
                            ctypes.POINTER(ctypes.POINTER(IEnumVdsObject)),
                            'ppEnum'))
    ]


class IVdsDisk(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{07e5c822-f00c-47a1-8fce-b244da56fd06}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetProperties',
                           (['out'], ctypes.POINTER(VDS_DISK_PROP),
                            'pDiskProperties')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetPack',
                           (['out'], ctypes.POINTER(ctypes.POINTER(IVdsPack)),
                            'ppPack')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetIdentificationData',
                           (['out'], ctypes.c_void_p, 'pLunInfo')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'QueryExtents',
                           (['out'], ctypes.POINTER(ctypes.POINTER(
                                                    VDS_DISK_EXTENT)),
                            'ppExtentArray'),
                           (['out'], ctypes.POINTER(wintypes.LONG),
                            'plNumberOfExtents')),
    ]


class IVdsAsync(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{d5d23b6d-5a55-4492-9889-397a3c2d2dbc}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'Cancel'),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'Wait',
                           (['out'], ctypes.POINTER(
                               ctypes.HRESULT), 'pHrResult'),
                           (['out'], ctypes.POINTER(VDS_ASYNC_OUTPUT),
                            'pAsyncOut')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'QueryStatus',
                           (['out'], ctypes.POINTER(
                            ctypes.HRESULT), 'pHrResult'),
                           (['out'], ctypes.POINTER(wintypes.ULONG),
                            'pulPercentCompleted')),
    ]


class IVdsVolume(comtypes.IUnknown):
    _iid_ = comtypes.GUID("{88306bb2-e71f-478c-86a2-79da200a0f11}")

    _methods_ = [
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetProperties',
                           (['out'], ctypes.POINTER(VDS_VOLUME_PROP),
                            'pVolumeProperties')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'GetPack',
                           (['out'], ctypes.POINTER(ctypes.POINTER(IVdsPack)),
                            'ppPack')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'QueryPlexes',
                           (['out'],
                            ctypes.POINTER(ctypes.POINTER(IEnumVdsObject)),
                            'ppEnum')),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'Extend',
                           (['in'], ctypes.POINTER(
                            VDS_INPUT_DISK), 'pInputDiskArray'),
                           (['in'], wintypes.LONG, 'lNumberOfDisks'),
                           (['out'], ctypes.POINTER(
                            ctypes.POINTER(IVdsAsync)), 'ppAsync'),
                           ),
        comtypes.COMMETHOD([], comtypes.HRESULT, 'Shrink',
                           (['in'], wintypes.ULARGE_INTEGER,
                            'ullNumberOfBytesToRemove'),
                           (['out'], ctypes.POINTER(ctypes.POINTER(IVdsAsync)),
                            'ppAsync')),
    ]


def load_vds_service():
    loader = client.CreateObject(CLSID_VdsLoader, interface=IVdsServiceLoader)
    svc = loader.LoadService(None)
    svc.WaitForServiceReady()
    return svc
