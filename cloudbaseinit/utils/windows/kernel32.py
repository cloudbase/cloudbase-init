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

import ctypes

from ctypes import windll
from ctypes import wintypes

ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_DATA = 232


class GUID(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", wintypes.BYTE * 8)]

    def __init__(self, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8):
        self.data1 = l
        self.data2 = w1
        self.data3 = w2
        self.data4[0] = b1
        self.data4[1] = b2
        self.data4[2] = b3
        self.data4[3] = b4
        self.data4[4] = b5
        self.data4[5] = b6
        self.data4[6] = b7
        self.data4[7] = b8


GetProcessHeap = windll.kernel32.GetProcessHeap
GetProcessHeap.argtypes = []
GetProcessHeap.restype = wintypes.HANDLE

HeapAlloc = windll.kernel32.HeapAlloc
# Note: wintypes.ULONG must be replaced with a 64 bit variable on x64
HeapAlloc.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.ULONG]
HeapAlloc.restype = wintypes.LPVOID

HeapFree = windll.kernel32.HeapFree
HeapFree.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
HeapFree.restype = wintypes.BOOL
