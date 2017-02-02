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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.windows import displayidletimeout
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class DisplayIdleTimeoutConfigPluginTests(unittest.TestCase):

    def setUp(self):
        self._displayplugin = (displayidletimeout.
                               DisplayIdleTimeoutConfigPlugin())
        self.snatcher = testutils.LogSnatcher(
            'cloudbaseinit.plugins.windows.displayidletimeout')

    @mock.patch('cloudbaseinit.utils.windows.powercfg.'
                'set_display_idle_timeout')
    def test_execute(self, mock_set_display):
        expected_logging = [
            "Setting display idle timeout: %s" % CONF.display_idle_timeout]
        expected_result = (base.PLUGIN_EXECUTION_DONE, False)
        with self.snatcher:
            result = self._displayplugin.execute(mock.sentinel.service,
                                                 mock.sentinel.data)
        self.assertEqual(self.snatcher.output, expected_logging)
        self.assertEqual(result, expected_result)
        mock_set_display.assert_called_once_with(CONF.display_idle_timeout)

    def test_get_os_requirements(self):
        result = self._displayplugin.get_os_requirements()
        self.assertEqual(result, ('win32', (6, 2)))
