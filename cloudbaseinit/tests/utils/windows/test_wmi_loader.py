# Copyright 2018 Cloudbase Solutions Srl
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
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception

MODPATH = "cloudbaseinit.utils.windows.wmi_loader"


class WMILoaderTests(unittest.TestCase):
    def test_load_pymi(self):
        with mock.patch.dict('sys.modules', {'wmi': mock.sentinel.wmi}):
            wmi_loader = importlib.import_module(MODPATH)
            self.assertEqual(mock.sentinel.wmi, wmi_loader.wmi())

    @mock.patch('imp.load_source')
    @mock.patch('os.path.isfile')
    def test_load_legacy_wmi(self, mock_isfile, mock_load_source):
        mock_isfile.return_value = True

        mock_site = mock.MagicMock()
        fake_site_path = "fake_site_path"
        mock_site.getsitepackages.return_value = [fake_site_path]
        mock_load_source.return_value = mock.sentinel.wmi

        with mock.patch.dict('sys.modules', {'wmi': None, 'site': mock_site}):
            wmi_loader = importlib.import_module(MODPATH)
            self.assertEqual(mock.sentinel.wmi, wmi_loader.wmi())

        fake_wmi_path = os.path.join(fake_site_path, "wmi.py")
        mock_isfile.assert_called_once_with(fake_wmi_path)
        mock_load_source.assert_called_once_with("wmi", fake_wmi_path)

    @mock.patch('os.path.isfile')
    def test_load_legacy_wmi_fail(self, mock_isfile):
        mock_isfile.return_value = False

        mock_site = mock.MagicMock()
        fake_site_path = "fake_site_path"
        mock_site.getsitepackages.return_value = [fake_site_path]

        with mock.patch.dict('sys.modules', {'wmi': None, 'site': mock_site}):
            wmi_loader = importlib.import_module(MODPATH)
            self.assertRaises(
                exception.ItemNotFoundException, wmi_loader.wmi)

        fake_wmi_path = os.path.join(fake_site_path, "wmi.py")
        mock_isfile.assert_called_once_with(fake_wmi_path)
