# Copyright 2015 Cloudbase Solutions Srl
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

from cloudbaseinit.plugins.windows import createuser
from cloudbaseinit.tests import testutils


class CreateUserPluginTests(unittest.TestCase):

    def setUp(self):
        self._create_user = createuser.CreateUserPlugin()

    def test_create_user(self):
        mock_osutils = mock.Mock()
        self._create_user.create_user(
            mock.sentinel.username,
            mock.sentinel.password,
            mock_osutils)

        mock_osutils.create_user.assert_called_once_with(
            mock.sentinel.username,
            mock.sentinel.password)

    @mock.patch('cloudbaseinit.plugins.windows.createuser.CreateUserPlugin.'
                '_create_user_logon')
    def test_post_create_user(self, mock_create_user_logon):
        mock_osutils = mock.Mock()
        self._create_user.post_create_user(
            mock.sentinel.username,
            mock.sentinel.password,
            mock_osutils)

        mock_create_user_logon.assert_called_once_with(
            mock.sentinel.username,
            mock.sentinel.password,
            mock_osutils)

    def test__create_user_logon(self):
        mock_osutils = mock.Mock()
        mock_token = mock.sentinel.token
        mock_osutils.create_user_logon_session.return_value = mock_token

        self._create_user._create_user_logon(
            mock.sentinel.user_name,
            mock.sentinel.password,
            mock_osutils)

        mock_osutils.create_user_logon_session.assert_called_once_with(
            mock.sentinel.user_name,
            mock.sentinel.password,
            True)
        mock_osutils.close_user_logon_session.assert_called_once_with(
            mock_token)

    def test__create_user_logon_fails(self):
        mock_osutils = mock.Mock()
        mock_osutils.create_user_logon_session.side_effect = Exception

        with testutils.LogSnatcher('cloudbaseinit.plugins.windows.'
                                   'createuser') as snatcher:
            self._create_user._create_user_logon(
                mock.sentinel.user_name,
                mock.sentinel.password,
                mock_osutils)

        mock_osutils.create_user_logon_session.assert_called_once_with(
            mock.sentinel.user_name,
            mock.sentinel.password,
            True)
        self.assertFalse(mock_osutils.close_user_logon_session.called)
        logging_message = (
            "Cannot create a user logon session for user: \"%s\""
            % mock.sentinel.user_name)
        self.assertTrue(snatcher.output[0].startswith(logging_message))
