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


MODPATH = "cloudbaseinit.utils.windows.updates"


class UpdatesUtilTest(unittest.TestCase):

    def setUp(self):
        self._win32_com = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules', {
                'win32com': self._win32_com})
        self._win32_com_client = self._win32_com.client
        self._module_patcher.start()
        self._updates = importlib.import_module(MODPATH)

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def _test_set_automatic_updates(self, mock_get_os_utils, enabled=True):
        mock_osutils = mock.Mock()
        mock_updates = mock.Mock()
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.check_os_version.return_value = False
        self._win32_com_client.Dispatch.return_value = mock_updates
        if not enabled:
            self._updates.set_automatic_updates(enabled)
            self.assertEqual(mock_updates.Settings.NotificationLevel, 1)
            mock_updates.Settings.Save.assert_called_once_with()
        else:
            self._updates.set_automatic_updates(enabled)
            mock_get_os_utils.assert_called_once_with()
            self.assertIsNotNone(
                mock_updates.SettingsScheduledInstallationTime)
        mock_updates.Settings.Save.assert_called_once_with()

    def test_set_automatic_no_updates(self):
        self._test_set_automatic_updates(enabled=False)

    def test_set_automatic_updates(self):
        self._test_set_automatic_updates()
