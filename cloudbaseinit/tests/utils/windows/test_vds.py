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


class WindowsVdsUtilsTests(unittest.TestCase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()
        self._comtypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes': self._ctypes_mock,
             'comtypes': self._comtypes_mock})

        self._module_patcher.start()

        self.vds = importlib.import_module("cloudbaseinit.utils.windows.vds")

    def tearDown(self):
        self._module_patcher.stop()

    def test_load_vds_service(self):
        mock_client = self._comtypes_mock.client.CreateObject.return_value
        svc = mock_client.LoadService.return_value

        response = self.vds.load_vds_service()

        self._comtypes_mock.client.CreateObject.assert_called_once_with(
            self.vds.CLSID_VdsLoader, interface=self.vds.IVdsServiceLoader)
        mock_client.LoadService.assert_called_with(None)
        svc.WaitForServiceReady.assert_called_once_with()
        self.assertEqual(svc, response)
