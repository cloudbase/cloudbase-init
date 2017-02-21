# Copyright (c) 2017 Cloudbase Solutions Srl
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

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


MODPATH = "cloudbaseinit.utils.windows.rdp"


class RdpTest(unittest.TestCase):

    def setUp(self):
        self._wmi_mock = mock.MagicMock()
        self._moves_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules', {
                'wmi': self._wmi_mock,
                'six.moves': self._moves_mock})
        self._winreg_mock = self._moves_mock.winreg
        self.snatcher = testutils.LogSnatcher(MODPATH)
        self._module_patcher.start()
        self.rdp = importlib.import_module(MODPATH)

    def tearDown(self):
        self._module_patcher.stop()

    def _test_get_rdp_certificate_thumbprint(self, mock_cert=None):

        conn = self._wmi_mock.WMI
        mock_win32ts = mock.Mock()
        conn.return_value = mock_win32ts
        mock_win32ts.Win32_TSGeneralSetting.return_value = mock_cert
        if not mock_cert:
            self.assertRaises(exception.ItemNotFoundException,
                              self.rdp.get_rdp_certificate_thumbprint)
        else:
            res = self.rdp.get_rdp_certificate_thumbprint()
            self.assertEqual(res, mock.sentinel.cert)
        mock_win32ts.Win32_TSGeneralSetting.assert_called_once_with()
        conn.assert_called_once_with(moniker='//./root/cimv2/TerminalServices')

    def test_get_rdp_certificate_thumbprint_no_cert(self):
        self._test_get_rdp_certificate_thumbprint()

    def test_get_rdp_certificate_thumbprint(self):
        mock_c = mock.MagicMock()
        mock_c.SSLCertificateSHA1Hash = mock.sentinel.cert
        mock_cert = mock.MagicMock()
        mock_cert.__getitem__.return_value = mock_c
        self._test_get_rdp_certificate_thumbprint(mock_cert=mock_cert)

    def test_set_rdp_keepalive(self):
        enable_value = True
        expected_logs = [
            "Setting RDP KeepAliveEnabled: %s" % enable_value,
            "Setting RDP keepAliveInterval (minutes): %s" % 1]
        with self.snatcher:
            self.rdp.set_rdp_keepalive(enable_value)
        self.assertEqual(self.snatcher.output, expected_logs)
        self._winreg_mock.OpenKey.assert_called_once_with(
            self._winreg_mock.HKEY_LOCAL_MACHINE,
            'SOFTWARE\\Policies\\Microsoft\\'
            'Windows NT\\Terminal Services',
            0, self._winreg_mock.KEY_ALL_ACCESS)
        self.assertEqual(self._winreg_mock.SetValueEx.call_count, 2)
