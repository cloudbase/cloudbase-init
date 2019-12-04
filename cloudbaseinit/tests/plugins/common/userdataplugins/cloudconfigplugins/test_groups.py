# Copyright 2019 Cloudbase Solutions Srl
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
from oslo_config import cfg

from cloudbaseinit import exception
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    groups
)
from cloudbaseinit.tests import testutils

CONF = cfg.CONF
MODPATH = ("cloudbaseinit.plugins.common.userdataplugins."
           "cloudconfigplugins.groups")


class GroupsPluginTests(unittest.TestCase):

    def setUp(self):
        self.groups_plugin = groups.GroupsPlugin()

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_group_empty(self, mock_get_os_utils):
        fake_data = ['']

        with testutils.LogSnatcher(MODPATH) as snatcher:
            res = self.groups_plugin.process(fake_data)
        self.assertEqual(['Group name cannot be empty'], snatcher.output)
        self.assertEqual(res, False)

    def test_process_group_wrong_content(self):
        fake_data = 'fake_group'

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self.groups_plugin.process(fake_data)
        expected = "Can't process the type of data %s" % type(fake_data)
        self.assertEqual(expected, str(cm.exception))

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_group(self, mock_get_os_utils):
        fake_data = [{'group1': ['usr1', 'usr2']}]
        mock_os_util = mock.MagicMock()
        mock_os_util.add_user_to_local_group.return_value = True
        mock_os_util.group_exists.return_value = True
        mock_get_os_utils.return_value = mock_os_util

        with testutils.LogSnatcher(MODPATH) as snatcher:
            res = self.groups_plugin.process(fake_data)
        self.assertEqual(["Group 'group1' already exists"], snatcher.output)
        self.assertEqual(res, False)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_group_fail(self, mock_get_os_utils):
        fake_data = [{'group1': ['usr1']}]
        mock_os_util = mock.MagicMock()
        mock_os_util.create_group.return_value = True
        mock_os_util.add_user_to_local_group.side_effect = Exception
        mock_os_util.group_exists.return_value = False
        mock_get_os_utils.return_value = mock_os_util

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self.groups_plugin.process(fake_data)
        expected = "Group 'group1' could not be configured. Exception code: "
        self.assertEqual(expected, str(cm.exception))
