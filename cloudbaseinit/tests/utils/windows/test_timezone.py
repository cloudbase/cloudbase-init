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

import importlib
import os
import struct
import unittest
try:
    import unittest.mock as mock
except ImportError:
    import mock


from cloudbaseinit import exception


class FakeWindowsError(Exception):
    pass


class TestTimezone(unittest.TestCase):

    def setUp(self):
        self._mock_moves = mock.MagicMock()
        self._mock_winreg = mock.Mock()
        self._mock_ctypes = mock.Mock()
        self._mock_win32security = mock.Mock()
        self._mock_win32process = mock.Mock()
        self._mock_wintypes = mock.MagicMock()
        self._mock_ctypes.wintypes = self._mock_wintypes
        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._mock_ctypes,
             'six.moves': self._mock_moves,
             'win32process': self._mock_win32process,
             'win32security': self._mock_win32security})
        self._module_patcher.start()
        self._mock_moves.winreg = self._mock_winreg
        self._timezone_module = importlib.import_module(
            'cloudbaseinit.utils.windows.timezone')
        self._timezone_module.WindowsError = FakeWindowsError
        self._fixture_timezone_info = [
            0, 'StandardName', list(range(8)),
            3, "DaylightName", list(reversed(range(8))), 6,
        ]

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('cloudbaseinit.utils.windows.timezone.SYSTEMTIME')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_get_timezone_info', new=mock.MagicMock())
    def test__create_system_time(self, mock_systemtime):
        values = list(range(8))
        timezoneobj = self._timezone_module.Timezone(mock.sentinel.timezone)
        result = timezoneobj._create_system_time(values)
        mock_systemtime.assert_called_once_with()
        self.assertEqual(tuple(range(8)),
                         (result.wYear, result.wMonth, result.wDayOfWeek,
                          result.wDay, result.wHour, result.wMinute,
                          result.wSecond, result.wMilliseconds))

    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_create_system_time')
    @mock.patch('cloudbaseinit.utils.windows.timezone.TIME_ZONE_INFORMATION')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_get_timezone_info')
    def test__get_timezone_struct(self, mock_get_timezone_info,
                                  mock_time_zone_information,
                                  mock_create_system_time):
        mock_get_timezone_info.return_value = self._fixture_timezone_info

        timezoneobj = self._timezone_module.Timezone(mock.sentinel.timezone)
        result = timezoneobj._get_timezone_struct()

        mock_time_zone_information.assert_called_once_with()
        self.assertEqual(0, result.Bias)
        self.assertEqual('StandardName', result.StandardName)
        self.assertEqual(result.StandardDate,
                         mock_create_system_time.return_value)
        self.assertEqual(result.DaylightDate,
                         mock_create_system_time.return_value)
        self.assertEqual(3, result.StandardBias)
        self.assertEqual("DaylightName", result.DaylightName)
        self.assertEqual(6, result.DaylightBias)

    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_create_system_time')
    @mock.patch('cloudbaseinit.utils.windows.timezone.'
                'DYNAMIC_TIME_ZONE_INFORMATION')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_get_timezone_info')
    def test__get_dynamic_timezone_struct(self, mock_get_timezone_info,
                                          mock_dynamic_time_zone_information,
                                          mock_create_system_time):

        mock_get_timezone_info.return_value = self._fixture_timezone_info

        timezoneobj = self._timezone_module.Timezone("timezone name")
        result = timezoneobj._get_dynamic_timezone_struct()

        mock_dynamic_time_zone_information.assert_called_once_with()
        self.assertEqual(0, result.Bias)
        self.assertEqual('StandardName', result.StandardName)
        self.assertEqual(3, result.StandardBias)
        self.assertEqual("DaylightName", result.DaylightName)
        self.assertEqual(6, result.DaylightBias)
        self.assertFalse(result.DynamicDaylightTimeDisabled)
        self.assertEqual("timezone name", result.TimeZoneKeyName)
        self.assertEqual(result.StandardDate,
                         mock_create_system_time.return_value)
        self.assertEqual(result.DaylightDate,
                         mock_create_system_time.return_value)

    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_unpack_timezone_info')
    def test__get_timezone_info(self, mock_unpack_timezone_info):
        mock_unpack_timezone_info.return_value = range(7)
        registry_key = mock.MagicMock()
        self._mock_winreg.OpenKey.return_value = registry_key

        self._timezone_module.Timezone("timezone test")
        self._mock_winreg.OpenKey.assert_called_once_with(
            self._mock_winreg.HKEY_LOCAL_MACHINE,
            os.path.join(self._timezone_module.REG_TIME_ZONES,
                         "timezone test"))
        mock_unpack_timezone_info.assert_called_once_with(
            registry_key.__enter__.return_value)

    def test__get_time_zone_info_reraise_cloudbaseinit_exception(self):
        error = FakeWindowsError()
        error.errno = self._timezone_module.NOT_FOUND
        self._mock_winreg.OpenKey.side_effect = error

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self._timezone_module.Timezone("timezone test")
        self.assertEqual("Timezone 'timezone test' not found",
                         str(cm.exception))

    def test__get_time_zone_info_reraise_exception(self):
        error = FakeWindowsError()
        error.errno = 404
        self._mock_winreg.OpenKey.side_effect = error

        with self.assertRaises(FakeWindowsError) as cm:
            self._timezone_module.Timezone("timezone test")
        self.assertIsInstance(cm.exception, FakeWindowsError)
        self.assertEqual(404, cm.exception.errno)

    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_query_tz_key')
    def test__get_time_zone_info_real_data(self, mock_query_tz_key):
        orig_unpack = struct.unpack

        def unpacker(format, blob):
            if format == "l":
                format = "i"
            return orig_unpack(format, blob)

        mock_query_tz_key.return_value = (
            b'\xf0\x00\x00\x00\x00\x00\x00\x00\xc4\xff\xff\xff\x00\x00'
            b'\x0b\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x03\x00\x00\x00\x02\x00\x02\x00\x00\x00\x00\x00'
            b'\x00\x00',
            "Atlantic Standard Time",
            "Atlantic Daylight Time",
        )
        registry_key = mock.MagicMock()
        self._mock_winreg.OpenKey.return_value = registry_key

        with mock.patch('struct.unpack', side_effect=unpacker):
            timezoneobj = self._timezone_module.Timezone("timezone test")

        mock_query_tz_key.assert_called_once_with(registry_key.__enter__())
        self.assertEqual(240, timezoneobj.bias)
        self.assertEqual(-60, timezoneobj.daylight_bias)
        self.assertEqual((0, 3, 0, 2, 2, 0, 0, 0),
                         timezoneobj.daylight_date)
        self.assertEqual('Atlantic Daylight Time', timezoneobj.daylight_name)
        self.assertEqual(0, timezoneobj.standard_bias)
        self.assertEqual((0, 11, 0, 1, 2, 0, 0, 0),
                         timezoneobj.standard_date)
        self.assertEqual('Atlantic Standard Time', timezoneobj.standard_name)

    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_get_timezone_info')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_set_dynamic_time_zone_information')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_set_time_zone_information')
    def _test_set_time_zone_information(
            self, mock__set_time_zone_information,
            mock__set_dynamic_time_zone_information,
            mock_get_timezone_info, windows_60=True):
        mock_osutils = mock.Mock()
        mock_osutils.check_os_version.return_value = windows_60
        mock_get_timezone_info.return_value = self._fixture_timezone_info

        timezoneobj = self._timezone_module.Timezone("fake")
        timezoneobj.set(mock_osutils)

        if windows_60:
            mock__set_dynamic_time_zone_information.assert_called_once_with()
        else:
            mock__set_time_zone_information.assert_called_once_with()

    def test_set_daylight_not_supported(self):
        self._test_set_time_zone_information(windows_60=False)

    def test_set_daylight_supported(self):
        self._test_set_time_zone_information(windows_60=True)

    @mock.patch('cloudbaseinit.utils.windows.privilege.acquire_privilege')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_get_timezone_info')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_get_timezone_struct')
    @mock.patch('cloudbaseinit.utils.windows.timezone.Timezone.'
                '_get_dynamic_timezone_struct')
    def _test__set_time_zone_information(
            self, mock__get_dynamic_timezone_struct,
            mock__get_timezone_struct,
            mock_get_timezone_info,
            mock_acquire_privilege,
            windows_60=True,
            privilege=None):
        mock_get_timezone_info.return_value = self._fixture_timezone_info

        mock__get_timezone_struct.return_value = (
            mock.sentinel.timezone_struct,
        )
        mock__get_dynamic_timezone_struct.return_value = (
            mock.sentinel.timezone_struct,
        )

        timezoneobj = self._timezone_module.Timezone("fake")
        if windows_60:
            timezoneobj._set_dynamic_time_zone_information()
            mock__get_dynamic_timezone_struct.assert_called_once_with()
        else:
            timezoneobj._set_time_zone_information()
            mock__get_timezone_struct.assert_called_once_with()

        mock_acquire_privilege.assert_called_once_with(privilege)
        if windows_60:
            self._mock_ctypes.windll.kernel32.SetDynamicTimeZoneInformation(
                self._mock_ctypes.byref(mock.sentinel.timezone_struct))
        else:
            self._mock_ctypes.windll.kernel32.SetTimeZoneInformation(
                self._mock_ctypes.byref(mock.sentinel.timezone_struct))

    def test__set_time_zone_information(self):
        self._test__set_time_zone_information(
            windows_60=False,
            privilege=self._mock_win32security.SE_SYSTEMTIME_NAME)

    def test__set_dynamic_time_zone_information(self):
        self._test__set_time_zone_information(
            windows_60=True,
            privilege=self._mock_win32security.SE_TIME_ZONE_NAME)
