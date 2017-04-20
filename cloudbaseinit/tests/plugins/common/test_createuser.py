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
        password = "fake password"
        mock_osutils = mock.MagicMock()
        max_length = len(password)
        mock_osutils.generate_random_password.return_value = "*" * max_length
        with testutils.ConfPatcher('user_password_length', len(password)):
            response = self._create_user._get_password(mock_osutils)

        mock_osutils.generate_random_password.assert_called_once_with(
            max_length)
        self.assertEqual("*" * max_length, response)
        self.assertEqual(len(response), max_length)

    @testutils.ConfPatcher('groups', ['Admins'])
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.common.createuser.'
                'BaseCreateUserPlugin._get_password')
    @mock.patch.object(CreateUserPlugin, 'create_user')
    @mock.patch.object(CreateUserPlugin, 'post_create_user')
    def _test_execute(self, mock_post_create_user, mock_create_user,
                      mock_get_password, mock_get_os_utils,
                      user_exists=False, group_adding_works=True,
                      rename_admin_user=False, rename_admin_taken=False):
        shared_data = {}
        mock_osutils = mock.MagicMock()
        mock_service = mock.MagicMock()
        mock_service.get_admin_username.return_value = CONF.username
        mock_get_password.return_value = 'password'
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.user_exists.return_value = user_exists
        if rename_admin_user:
            mock_osutils.is_builtin_admin.return_value = True
            if rename_admin_taken:
                mock_osutils.enum_users.return_value = [CONF.username]
            else:
                mock_osutils.enum_users.return_value = ["fake user name"]
        if not group_adding_works:
            mock_osutils.add_user_to_local_group.side_effect = Exception

        with testutils.ConfPatcher('rename_admin_user', rename_admin_user):
            with testutils.LogSnatcher("cloudbaseinit.plugins.common."
                                       "createuser") as snatcher:
                response = self._create_user.execute(mock_service, shared_data)

        mock_get_os_utils.assert_called_once_with()
        mock_get_password.assert_called_once_with(mock_osutils)

        if user_exists:
            mock_osutils.user_exists.assert_called_once_with(CONF.username)
            mock_osutils.set_user_password.assert_called_once_with(
                CONF.username, 'password')
            expected_logging = ["Setting password for existing user \"%s\""
                                % CONF.username]
        elif rename_admin_user:
            if rename_admin_taken:
                expected_logging = [
                    '"%s" is already the name of the builtin admin '
                    'user, skipping renaming' % CONF.username
                ]
            else:
                expected_logging = [
                    'Renaming builtin admin user "{admin_user_name}" '
                    'to {new_user_name} and setting password'.format(
                        admin_user_name="fake user name",
                        new_user_name=CONF.username)
                ]
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

    def test_execute_rename_admin(self):
        self._test_execute(
            user_exists=False,
            rename_admin_user=True)

    def test_execute_rename_admin_taken(self):
        self._test_execute(rename_admin_user=True,
                           rename_admin_taken=True)
