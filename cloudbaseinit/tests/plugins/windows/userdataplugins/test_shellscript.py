# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions Srl
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

import mock
import os
import unittest

from oslo.config import cfg

from cloudbaseinit.plugins.windows.userdataplugins import shellscript

CONF = cfg.CONF


class ShellScriptPluginTests(unittest.TestCase):

    def setUp(self):
        self._shellscript = shellscript.ShellScriptPlugin()

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('tempfile.gettempdir')
    def _test_process(self, mock_gettempdir, mock_get_os_utils, filename,
                      exception=False):
        fake_dir_path = os.path.join("fake", "dir")
        mock_osutils = mock.MagicMock()
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = filename
        mock_gettempdir.return_value = fake_dir_path
        mock_get_os_utils.return_value = mock_osutils
        fake_target = os.path.join(fake_dir_path, filename)
        if exception:
            mock_osutils.execute_process.side_effect = [Exception]
        with mock.patch("cloudbaseinit.plugins.windows.userdataplugins."
                        "shellscript.open", mock.mock_open(), create=True):
            response = self._shellscript.process(mock_part)
        mock_part.get_filename.assert_called_once_with()
        mock_gettempdir.assert_called_once_with()
        if filename.endswith(".cmd"):
            mock_osutils.execute_process.assert_called_once_with(
                [fake_target], True)
        elif filename.endswith(".sh"):
            mock_osutils.execute_process.assert_called_once_with(
                ['bash.exe', fake_target], False)
        elif filename.endswith(".py"):
            mock_osutils.execute_process.assert_called_once_with(
                ['python.exe', fake_target], False)
        elif filename.endswith(".ps1"):
            mock_osutils.execute_powershell_script.assert_called_once_with(
                fake_target)
        else:
            self.assertEqual(response, 0)

    def test_process_cmd(self):
        self._test_process(filename='fake.cmd')

    def test_process_sh(self):
        self._test_process(filename='fake.sh')

    def test_process_py(self):
        self._test_process(filename='fake.py')

    def test_process_ps1(self):
        self._test_process(filename='fake.ps1')

    def test_process_other(self):
        self._test_process(filename='fake.other')

    def test_process_exception(self):
        self._test_process(filename='fake.cmd', exception=True)
