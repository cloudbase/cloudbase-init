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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.utils.windows import powercfg


class PowerCfgTests(unittest.TestCase):

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_set_display_idle_timeout(self, mock_get_osutils, fail=False):
        mock_osutils = mock.Mock()
        mock_get_osutils.return_value = mock_osutils
        mock_out = 1
        mock_err = None
        mock_ret_val = None
        expected_args = ["powercfg.exe", "/setacvalueindex", "SCHEME_CURRENT",
                         "SUB_VIDEO", "VIDEOIDLE", str(0)]
        if fail:
            mock_ret_val = 1
            mock_err = 1
        mock_osutils.execute_system32_process.return_value = (mock_out,
                                                              mock_err,
                                                              mock_ret_val)
        if fail:
            self.assertRaises(exception.CloudbaseInitException,
                              powercfg.set_display_idle_timeout)
        else:
            powercfg.set_display_idle_timeout()
        mock_get_osutils.assert_called_once_with()
        (mock_osutils.
            execute_system32_process.assert_called_once_with(expected_args))

    def test_set_display_idle_timeout(self):
        self._test_set_display_idle_timeout()

    def test_set_display_idle_timeout_fail(self):
        self._test_set_display_idle_timeout(fail=True)
