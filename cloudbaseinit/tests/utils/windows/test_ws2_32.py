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

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock


class WS2_32UtilsTests(unittest.TestCase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._ctypes_mock})

        self._module_patcher.start()

        self.ws2_32 = importlib.import_module(
            "cloudbaseinit.utils.windows.ws2_32")

    def tearDown(self):
        self._module_patcher.stop()

    def test_init_wsa(self):
        with mock.patch.object(self.ws2_32, 'WSADATA') as mock_WSADATA:
            self.ws2_32.init_wsa()

            mock_WSADATA.assert_called_once_with()

            self._ctypes_mock.windll.Ws2_32.WSAStartup.assert_called_once_with(
                self.ws2_32.VERSION_2_2, self._ctypes_mock.byref.return_value)

            self._ctypes_mock.byref.assert_called_once_with(
                mock_WSADATA.return_value)
