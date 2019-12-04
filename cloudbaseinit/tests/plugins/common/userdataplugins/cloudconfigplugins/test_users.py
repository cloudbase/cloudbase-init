# Copyright 2016 Cloudbase Solutions Srl
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
    users
)
from cloudbaseinit.tests import testutils

CONF = cfg.CONF
MODPATH = ("cloudbaseinit.plugins.common.userdataplugins."
           "cloudconfigplugins.users")


class UsersPluginTests(unittest.TestCase):

    def setUp(self):
        self.users_plugin = users.UsersPlugin()

    def test__get_groups(self):
        fake_data = {'groups': 'fake1, fake2', 'primary_group': 'fake3'}
        res = self.users_plugin._get_groups(fake_data)
        self.assertEqual(res, ['fake1', 'fake2', 'fake3'])

    def test__get_password(self):
        fake_password = 'Passw0rd'
        fake_data = {"passwd": fake_password}
        mock_os_utils = mock.MagicMock()
        mock_os_utils.get_maximum_password_length.return_value = 10
        res = self.users_plugin._get_password(fake_data, mock_os_utils)
        self.assertEqual(res, fake_password)

    def test__get_expire_interval(self):
        fake_data = {"expiredate": '2020-01-01'}
        res = self.users_plugin._get_expire_interval(fake_data)
        self.assertEqual(res, 1577836800)

    @mock.patch(MODPATH + '.UsersPlugin._get_password')
    @mock.patch(MODPATH + '.UsersPlugin._create_user_logon')
    @mock.patch(MODPATH + '.UsersPlugin._set_ssh_public_keys')
    def test__create_user(self, mock_set_ssh_keys, mock_user_logon,
                          mock_get_pass):
        fake_user = {
            'name': 'fake_user',
            'gecos': 'fake user',
            'primary_group': 'Users',
            'groups': 'test',
            'ssh_authorized_keys': ["test2", "test1"],
            'inactive': False,
            'expiredate': '3020-09-01',
            'passwd': 'Passw0rd'
        }
        mock_get_pass.return_value = 'fake_pass'
        mock_os_utils = mock.MagicMock()
        mock_os_utils.user_exists.return_value = False

        res = self.users_plugin._create_user(fake_user, mock_os_utils)
        self.assertEqual(res, None)
        mock_os_utils.create_user.assert_called_with('fake_user', 'fake_pass')
        mock_os_utils.set_user_info.assert_called_with(
            'fake_user', disabled=False, expire_interval=33155827200.0,
            full_name='fake user')
        mock_os_utils.add_user_to_local_group.assert_called_with(
            'fake_user', 'Users')
        mock_set_ssh_keys.assert_called_with('fake_user', ['test2', 'test1'],
                                             mock_os_utils)
        mock_user_logon.assert_called_with('fake_user', 'fake_pass',
                                           mock_os_utils)
        mock_get_pass.assert_called_with(fake_user, mock_os_utils)

    @mock.patch(MODPATH + '.UsersPlugin._get_password')
    def test__create_user_inactive_with_create_home(self, mock_get_pass):
        fake_user = {
            'inactive': True,
            'expiredate': '3020-09-01',
            'no_create_home': False
        }
        mock_get_pass.return_value = 'fake_pass'
        mock_os_utils = mock.MagicMock()

        with self.assertRaises(exception.CloudbaseInitException) as cm:
            self.users_plugin._create_user(fake_user, mock_os_utils)
            expected = ("The user is required to be enabled if public_keys "
                        "or create_home are set")
            self.assertEqual(expected, str(cm.exception))

    @mock.patch(MODPATH + '.UsersPlugin._create_user')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_user(self, mock_get_os_utils, mock_create_user):
        fake_data = [
            {
                'name': 'fake_user',
                'gecos': 'fake user name',
                'primary_group': 'Users',
                'groups': 'test',
                'ssh_authorized_keys': ["test2", "test1"],
                'inactive': False,
                'expiredate': '2020-09-01',
                'passwd': 'Passw0rd'
            }
        ]
        with testutils.LogSnatcher(MODPATH) as snatcher:
            res = self.users_plugin.process(fake_data)
        self.assertEqual([], snatcher.output)
        self.assertEqual(res, False)
