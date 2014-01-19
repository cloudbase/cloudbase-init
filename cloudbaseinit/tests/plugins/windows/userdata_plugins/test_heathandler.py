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

import importlib
import mock
import unittest

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.plugins.windows import userdata_plugins
#the name of the module includes "-", importlib.import_module is needed:
heathandler = importlib.import_module("cloudbaseinit.plugins.windows"
                                      ".userdata-plugins.heathandler")

CONF = cfg.CONF


class HeatUserDataHandlerTests(unittest.TestCase):

    def setUp(self):
        parent_set = userdata_plugins.PluginSet
        self._heathandler = heathandler.HeatUserDataHandler(parent_set)

    @mock.patch('cloudbaseinit.plugins.windows.userdata.handle')
    def test_process(self, mock_handle):
        mock_part = mock.MagicMock()
        mock_part.get_filename.return_value = "cfn-userdata"
        self._heathandler.process(mock_part)
        mock_part.get_filename.assert_called_once_with()
        mock_handle.assert_called_once_with(mock_part.get_payload())
