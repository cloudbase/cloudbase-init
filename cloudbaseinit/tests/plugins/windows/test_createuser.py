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

import mock
import unittest

from oslo.config import cfg

from cloudbaseinit.plugins import base
from cloudbaseinit.plugins.windows import createuser

CONF = cfg.CONF


class CreateUserPluginTests(unittest.TestCase):

    def setUp(self):
        self._create_user = createuser.CreateUserPlugin()

    def test_get_password(self):
        mock_osutils = mock.MagicMock()
        mock_osutils.generate_random_password.return_value = 'fake password'
        response = self._create_user._get_password(mock_osutils)
        mock_osutils.generate_random_password.assert_called_once_with(14)
        self.assertEqual('fake password', response)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.windows.createuser.CreateUserPlugin'
                '._get_password')
    def _test_execute(self, mock_get_password, mock_get_os_utils,
                      user_exists=True):
        CONF.set_override('groups', ['Admins'])
        shared_data = {}
        mock_token = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        mock_service = mock.MagicMock()
        mock_get_password.return_value = 'password'
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.user_exists.return_value = user_exists
        mock_osutils.create_user_logon_session.return_value = mock_token

        response = self._create_user.execute(mock_service, shared_data)

        mock_get_os_utils.assert_called_once_with()
        mock_get_password.assert_called_once_with(mock_osutils)
        mock_osutils.user_exists.assert_called_once_with(CONF.username)
        if user_exists:
            mock_osutils.set_user_password.assert_called_once_with(
                CONF.username, 'password')
        else:
            mock_osutils.create_user.assert_called_once_with(CONF.username,
                                                             'password')
            mock_osutils.create_user_logon_session.assert_called_once_with(
                CONF.username, 'password', True)
            mock_osutils.close_user_logon_session.assert_called_once_with(
                mock_token)
        mock_osutils.add_user_to_local_group.assert_called_once_with(
            CONF.username, CONF.groups[0])
        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute_user_exists(self):
        self._test_execute(user_exists=True)

    def test_execute_no_user(self):
        self._test_execute(user_exists=False)
