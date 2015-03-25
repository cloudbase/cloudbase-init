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

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


class TestException(testutils.CloudbaseInitTestBase):

    @mock.patch('ctypes.GetLastError', create=True)
    @mock.patch('ctypes.FormatError', create=True)
    def _test_windows_exception(self, mock_format_error,
                                mock_get_last_error, message="Test %r",
                                description="test",
                                error_code=None):

        mock_format_error.return_value = description
        mock_get_last_error.return_value = mock.sentinel.error_code

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            raise exception.WindowsCloudbaseInitException(message, error_code)

        if error_code is None:
            mock_get_last_error.assert_called_once_with()
            error_code = mock.sentinel.error_code

        try:
            expected = message % description
        except TypeError:
            expected = message

        mock_format_error.assert_called_once_with(error_code)
        self.assertEqual(expected, str(cm.exception))

    def test_windows_exception_no_error_code_given(self):
        self._test_windows_exception()

    def test_windows_exception_error_code_given(self):
        self._test_windows_exception(error_code=100)

    def test_windows_exception_no_formatting_allowed(self):
        self._test_windows_exception(message="Test")
