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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.plugins.windows.rdp"


class RDPPluginTest(unittest.TestCase):

    def setUp(self):
        self.mock_wmi = mock.MagicMock()
        self._moves_mock = mock.MagicMock()
        patcher = mock.patch.dict(
            "sys.modules",
            {
                "wmi": self.mock_wmi,
                "six.moves": self._moves_mock
            }
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        rdp = importlib.import_module(
            "cloudbaseinit.plugins.windows.rdp")
        self.rdp_settings = rdp.RDPSettingsPlugin()
        self.rdp_post = rdp.RDPPostCertificateThumbprintPlugin()
        self.snatcher = testutils.LogSnatcher(MODPATH)

    @mock.patch("cloudbaseinit.utils.windows.rdp."
                "get_rdp_certificate_thumbprint")
    def _test_execute_post(self, mock_get_rdp, mock_service=None,
                           mock_shared_data=None):
        expected_res = (base.PLUGIN_EXECUTION_DONE, False)
        expected_logs = []
        mock_get_rdp.return_value = mock.sentinel.cert
        with self.snatcher:
            res = self.rdp_post.execute(mock_service, mock_shared_data)
        if not mock_service.can_post_rdp_cert_thumbprint:
            expected_logs.append("The service does not provide the capability"
                                 " to post the RDP certificate thumbprint")
        else:
            expected_logs.append("Posting the RDP certificate thumbprint: %s"
                                 % mock.sentinel.cert)
            mock_get_rdp.assert_called_once_with()
            mock_service.post_rdp_cert_thumbprint.assert_called_once_with(
                mock.sentinel.cert)

        self.assertEqual(res, expected_res)
        self.assertEqual(self.snatcher.output, expected_logs)

    @mock.patch("cloudbaseinit.utils.windows.rdp.set_rdp_keepalive")
    def _test_execute_settings(self, mock_set_rdp, mock_service=None,
                               mock_shared_data=None):
        expected_res = (base.PLUGIN_EXECUTION_DONE, False)
        expected_logs = ["Setting RDP KeepAlive: %s" % CONF.rdp_set_keepalive]
        with self.snatcher:
            res = self.rdp_settings.execute(mock_service, mock_shared_data)
        self.assertEqual(res, expected_res)
        self.assertEqual(self.snatcher.output, expected_logs)
        mock_set_rdp.assert_called_once_with(CONF.rdp_set_keepalive)

    def test_execute_set_rdp(self):
        mock_service = mock.Mock()
        self._test_execute_settings(mock_service=mock_service)

    def test_execute_can_not_post(self):
        mock_service = mock.Mock()
        mock_service.can_post_rdp_cert_thumbprint = False
        self._test_execute_post(mock_service=mock_service)

    def test_execute_can_post(self):
        mock_service = mock.Mock()
        mock_service.can_post_rdp_cert_thumbprint = True
        self._test_execute_post(mock_service=mock_service)

    def test_get_os_requirements(self):
        expected_res = ('win32', (5, 2))
        res_settings = self.rdp_settings.get_os_requirements()
        res_post = self.rdp_post.get_os_requirements()
        for res in (res_settings, res_post):
            self.assertEqual(res, expected_res)
