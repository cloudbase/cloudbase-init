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

import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.windows import licensing
from cloudbaseinit.tests import testutils


class WindowsLicensingPluginTests(unittest.TestCase):

    def setUp(self):
        self._licensing = licensing.WindowsLicensingPlugin()

    def _test_run_slmgr(self, sysnative, exit_code):
        mock_osutils = mock.MagicMock()
        get_system32_dir_calls = [mock.call()]
        cscript_path = os.path.join('cscrypt path', "cscript.exe")
        slmgr_path = os.path.join('slmgr path', "slmgr.vbs")

        mock_osutils.check_sysnative_dir_exists.return_value = sysnative
        mock_osutils.get_sysnative_dir.return_value = 'cscrypt path'
        if not sysnative:
            mock_osutils.get_system32_dir.side_effect = ['cscrypt path',
                                                         'slmgr path']
        else:
            mock_osutils.get_system32_dir.return_value = 'slmgr path'
        mock_osutils.execute_process.return_value = ('fake output', None,
                                                     exit_code)

        if exit_code:
            self.assertRaises(exception.CloudbaseInitException,
                              self._licensing._run_slmgr,
                              mock_osutils, ['fake args'])
        else:
            response = self._licensing._run_slmgr(osutils=mock_osutils,
                                                  args=['fake args'])
            self.assertEqual('fake output', response)

        mock_osutils.check_sysnative_dir_exists.assert_called_once_with()
        if sysnative:
            mock_osutils.get_sysnative_dir.assert_called_once_with()
        else:
            get_system32_dir_calls.append(mock.call())

        mock_osutils.execute_process.assert_called_once_with(
            [cscript_path, slmgr_path, 'fake args'],
            shell=False, decode_output=True)
        self.assertEqual(get_system32_dir_calls,
                         mock_osutils.get_system32_dir.call_args_list)

    def test_run_slmgr_sysnative(self):
        self._test_run_slmgr(sysnative=True, exit_code=None)

    def test_run_slmgr_not_sysnative(self):
        self._test_run_slmgr(sysnative=False, exit_code=None)

    def test_run_slmgr_exit_code(self):
        self._test_run_slmgr(sysnative=True, exit_code='fake exit code')

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.windows.licensing'
                '.WindowsLicensingPlugin._run_slmgr')
    def _test_execute(self, mock_run_slmgr, mock_get_os_utils,
                      activate_windows=None, nano=False):
        mock_osutils = mock.MagicMock()
        mock_osutils.is_nano_server.return_value = nano
        run_slmgr_calls = [mock.call(mock_osutils, ['/dlv'])]
        mock_get_os_utils.return_value = mock_osutils

        with testutils.ConfPatcher('activate_windows', activate_windows):
            response = self._licensing.execute(service=None, shared_data=None)

        mock_get_os_utils.assert_called_once_with()
        if nano:
            return    # no activation available
        if activate_windows:
            run_slmgr_calls.append(mock.call(mock_osutils, ['/ato']))

        self.assertEqual(run_slmgr_calls, mock_run_slmgr.call_args_list)
        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute_activate_windows_true(self):
        self._test_execute(activate_windows=True)

    def test_execute_activate_windows_false(self):
        self._test_execute(activate_windows=False)

    def test_execute_activate_windows_nano(self):
        self._test_execute(nano=True)
