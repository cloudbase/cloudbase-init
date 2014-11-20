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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.plugins.common.userdataplugins import cloudboothook


class CloudBootHookPluginTests(unittest.TestCase):

    def setUp(self):
        self._cloud_hook = cloudboothook.CloudBootHookPlugin()

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.base'
                '.BaseUserDataPlugin.get_mime_type')
    def test_process(self, mock_get_mime_type):
        mock_part = mock.MagicMock()
        self._cloud_hook.process(mock_part)
        mock_get_mime_type.assert_called_once_with()
