# Copyright 2015 Cloudbase Solutions Srl
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
from ctypes import wintypes
import os
import struct

from six.moves import winreg
import win32security

from cloudbaseinit import exception
from cloudbaseinit.utils.windows import privilege


REG_TIME_ZONES = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"
NOT_FOUND = 2
kernel32 = ctypes.windll.kernel32


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ('wYear', wintypes.WORD),
        ('wMonth', wintypes.WORD),
        ('wDayOfWeek', wintypes.WORD),
        ('wDay', wintypes.WORD),
        ('wHour', wintypes.WORD),
        ('wMinute', wintypes.WORD),
        ('wMilliseconds', wintypes.WORD),
    ]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('Bias', wintypes.LONG),
        ('StandardName', wintypes.WCHAR * 32),
        ('StandardDate', SYSTEMTIME),
        ('StandardBias', wintypes.LONG),
        ('DaylightName', wintypes.WCHAR * 32),
        ('DaylightDate', SYSTEMTIME),
        ('DaylightBias', wintypes.LONG),
    ]


class DYNAMIC_TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('Bias', wintypes.LONG),
        ('StandardName', wintypes.WCHAR * 32),
        ('StandardDate', SYSTEMTIME),
        ('StandardBias', wintypes.LONG),
        ('DaylightName', wintypes.WCHAR * 32),
        ('DaylightDate', SYSTEMTIME),
        ('DaylightBias', wintypes.LONG),
        ('TimeZoneKeyName', wintypes.WCHAR * 128),
        ('DynamicDaylightTimeDisabled', wintypes.BOOLEAN),
    ]


class Timezone(object):
    """Class which holds details about a particular timezone.

    It also can be used to change the current timezone,
    by calling the :meth:`~set`. The supported time zone names
    are the ones found here:
    https://technet.microsoft.com/en-us/library/cc749073%28v=ws.10%29.aspx
    """

    def __init__(self, name):
        self._name = name
        self._timezone_info = self._get_timezone_info()

        # Public API.
        self.bias = self._timezone_info[0]
        self.standard_name = self._timezone_info[1]
        self.standard_date = self._timezone_info[2]
        self.standard_bias = self._timezone_info[3]
        self.daylight_name = self._timezone_info[4]
        self.daylight_date = self._timezone_info[5]
        self.daylight_bias = self._timezone_info[6]

    @staticmethod
    def _create_system_time(values):
        mtime = SYSTEMTIME()
        mtime.wYear = values[0]
        mtime.wMonth = values[1]
        mtime.wDayOfWeek = values[2]
        mtime.wDay = values[3]
        mtime.wHour = values[4]
        mtime.wMinute = values[5]
        mtime.wSecond = values[6]
        mtime.wMilliseconds = values[7]
        return mtime

    def _get_timezone_struct(self):
        info = TIME_ZONE_INFORMATION()
        info.Bias = self.bias
        info.StandardName = self.standard_name
        info.StandardDate = self._create_system_time(self.standard_date)
        info.StandardBias = self.standard_bias
        info.DaylightName = self.daylight_name
        info.DaylightBias = self.daylight_bias
        info.DaylightDate = self._create_system_time(self.daylight_date)
        return info

    def _get_dynamic_timezone_struct(self):
        info = DYNAMIC_TIME_ZONE_INFORMATION()
        info.Bias = self.bias
        info.StandardName = self.standard_name
        info.StandardDate = self._create_system_time(self.standard_date)
        info.StandardBias = self.standard_bias
        info.DaylightName = self.daylight_name
        info.DaylightBias = self.daylight_bias
        info.DaylightDate = self._create_system_time(self.daylight_date)
        # TODO(cpopa): should this flag be controllable?
        info.DynamicDaylightTimeDisabled = False
        info.TimeZoneKeyName = self._name
        return info

    def _get_timezone_info(self):
        keyname = os.path.join(REG_TIME_ZONES, self._name)
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, keyname) as key:
                return self._unpack_timezone_info(key)
        except WindowsError as exc:
            if exc.errno == NOT_FOUND:
                raise exception.CloudbaseInitException(
                    "Timezone %r not found" % self._name)
            else:
                raise

    @staticmethod
    def _unpack_system_time(tzi, offset):
        # Unpack the values of a TIME_ZONE_INFORMATION structure
        # from the given blob, starting at the given offset.
        return [struct.unpack("H", tzi[index: index + 2])[0]
                for index in range(offset, offset + 16, 2)]

    @staticmethod
    def _query_tz_key(key):
        tzi = winreg.QueryValueEx(key, "TZI")[0]
        daylight_name = winreg.QueryValueEx(key, "Dlt")[0]
        standard_name = winreg.QueryValueEx(key, "Std")[0]
        return tzi, standard_name, daylight_name

    def _unpack_timezone_info(self, key):
        # Get information about the current timezone from the given
        # registry key.
        tzi, standard_name, daylight_name = self._query_tz_key(key)
        bias, = struct.unpack("l", tzi[:4])
        standard_bias, = struct.unpack("l", tzi[4:8])
        daylight_bias, = struct.unpack("l", tzi[8:12])
        standard_date = self._unpack_system_time(tzi, 12)
        daylight_date = self._unpack_system_time(tzi, 12 + 16)

        return (bias, standard_name, tuple(standard_date),
                standard_bias, daylight_name,
                tuple(daylight_date), daylight_bias)

    def _set_time_zone_information(self):
        info = self._get_timezone_struct()
        with privilege.acquire_privilege(win32security.SE_SYSTEMTIME_NAME):
            kernel32.SetTimeZoneInformation(ctypes.byref(info))

    def _set_dynamic_time_zone_information(self):
        info = self._get_dynamic_timezone_struct()
        with privilege.acquire_privilege(win32security.SE_TIME_ZONE_NAME):
            kernel32.SetDynamicTimeZoneInformation(ctypes.byref(info))

    def set(self, osutils):
        """Change the underlying timezone with this one.

        This will use SetDynamicTimeZoneInformation on Windows Vista+ and
        for Windows 2003 it will fallback to SetTimeZoneInformation, which
        doesn't handle Daylight Saving Time.
        """
        if osutils.check_os_version(6, 0):
            self._set_dynamic_time_zone_information()
        else:
            self._set_time_zone_information()
