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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import createuser
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class CreateUserPlugin(createuser.BaseCreateUserPlugin):

    def create_user(self, username, password, osutils):
        pass

    def post_create_user(self, username, password, osutils):
        pass


class CreateUserPluginTests(unittest.TestCase):

    def setUp(self):
        self._create_user = CreateUserPlugin()

    def test_get_password(self):
        mock_osutils = mock.MagicMock()
        mock_osutils.generate_random_password.return_value = 'fake password'
        response = self._create_user._get_password(mock_osutils)
        mock_osutils.get_maximum_password_length.assert_called_once_with()
        length = mock_osutils.get_maximum_password_length()
        mock_osutils.generate_random_password.assert_called_once_with(length)
        self.assertEqual('fake password', response)

    @testutils.ConfPatcher('groups', ['Admins'])
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.common.createuser.'
                'BaseCreateUserPlugin._get_password')
    @mock.patch.object(CreateUserPlugin, 'create_user')
    @mock.patch.object(CreateUserPlugin, 'post_create_user')
    def _test_execute(self, mock_post_create_user, mock_create_user,
                      mock_get_password, mock_get_os_utils,
                      user_exists=True,
                      group_adding_works=True):
        shared_data = {}
        mock_osutils = mock.MagicMock()
        mock_service = mock.MagicMock()
        mock_get_password.return_value = 'password'
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.user_exists.return_value = user_exists
        if not group_adding_works:
            mock_osutils.add_user_to_local_group.side_effect = Exception

        with testutils.LogSnatcher("cloudbaseinit.plugins.common."
                                   "createuser") as snatcher:
            response = self._create_user.execute(mock_service, shared_data)

        mock_get_os_utils.assert_called_once_with()
        mock_get_password.assert_called_once_with(mock_osutils)
        mock_osutils.user_exists.assert_called_once_with(CONF.username)
        if user_exists:
            mock_osutils.set_user_password.assert_called_once_with(
                CONF.username, 'password')
            expected_logging = ["Setting password for existing user \"%s\""
                                % CONF.username]
        else:
            mock_create_user.assert_called_once_with(
                CONF.username, 'password',
                mock_osutils)
            expected_logging = ["Creating user \"%s\" and setting password"
                                % CONF.username]

        mock_post_create_user.assert_called_once_with(
            CONF.username, 'password',
            mock_osutils)

        self.assertEqual(expected_logging, snatcher.output[:1])
        if not group_adding_works:
            failed = snatcher.output[1].startswith(
                "Cannot add user to group \"Admins\"")
            self.assertTrue(failed)

        mock_osutils.add_user_to_local_group.assert_called_once_with(
            CONF.username, CONF.groups[0])
        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute_user_exists(self):
        self._test_execute(user_exists=True)

    def test_execute_no_user(self):
        self._test_execute(user_exists=False)

    def test_execute_add_to_group_fails(self):
        self._test_execute(group_adding_works=False)
