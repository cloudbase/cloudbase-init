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

import mock

from cloudbaseinit.plugins.windows import setuserpassword
from cloudbaseinit.tests import testutils


@mock.patch.object(setuserpassword.factory, 'get_os_utils')
class TestSetUserPassword(unittest.TestCase):

    def setUp(self):
        self._plugin = setuserpassword.SetUserPasswordPlugin()

    @testutils.ConfPatcher('first_logon_behaviour',
                           setuserpassword.NEVER_CHANGE)
    def test_post_set_password_never_change(self, mock_get_os_utils):
        self._plugin.post_set_password(mock.sentinel.username,
                                       mock.sentinel.password)

        self.assertFalse(mock_get_os_utils.called)

    @testutils.ConfPatcher('first_logon_behaviour',
                           setuserpassword.ALWAYS_CHANGE)
    def test_post_set_password_always(self, mock_get_os_utils):
        self._plugin.post_set_password(mock.sentinel.username,
                                       mock.sentinel.password)

        self.assertTrue(mock_get_os_utils.called)
        osutils = mock_get_os_utils.return_value
        osutils.change_password_next_logon.assert_called_once_with(
            mock.sentinel.username)

    @testutils.ConfPatcher('first_logon_behaviour',
                           setuserpassword.CLEAR_TEXT_INJECTED_ONLY)
    def test_post_set_password_clear_text_password_not_injected(
            self, mock_get_os_utils):
        self._plugin.post_set_password(mock.sentinel.username,
                                       mock.sentinel.password,
                                       password_injected=False)

        self.assertFalse(mock_get_os_utils.called)

    @testutils.ConfPatcher('first_logon_behaviour',
                           setuserpassword.CLEAR_TEXT_INJECTED_ONLY)
    def test_post_set_password_clear_text_password_injected(
            self, mock_get_os_utils):
        self._plugin.post_set_password(mock.sentinel.username,
                                       mock.sentinel.password,
                                       password_injected=True)

        self.assertTrue(mock_get_os_utils.called)
        osutils = mock_get_os_utils.return_value
        osutils.change_password_next_logon.assert_called_once_with(
            mock.sentinel.username)
