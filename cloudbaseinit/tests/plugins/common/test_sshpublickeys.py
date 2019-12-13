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

import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import sshpublickeys
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils


class SetUserSSHPublicKeysPluginTests(unittest.TestCase):

    def setUp(self):
        self._set_ssh_keys_plugin = sshpublickeys.SetUserSSHPublicKeysPlugin()
        self.fake_data = fake_json_response.get_fake_metadata_json(
            '2013-04-04')

    @testutils.ConfPatcher('username', 'fake_username')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('os.path')
    @mock.patch('os.makedirs')
    def _test_execute(self, mock_os_makedirs, mock_os_path,
                      mock_get_os_utils, user_home,
                      metadata_provided_username=False):
        mock_service = mock.MagicMock()
        mock_osutils = mock.MagicMock()
        fake_shared_data = 'fake data'
        mock_service.get_public_keys.return_value = self.fake_data
        fake_username = 'fake_username'
        if metadata_provided_username:
            fake_username = mock.MagicMock()
            mock_service.get_admin_username.return_value = fake_username
        else:
            mock_service.get_admin_username.return_value = None
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.get_user_home.return_value = user_home
        mock_os_path.exists.return_value = False

        if user_home is None:
            self.assertRaises(exception.CloudbaseInitException,
                              self._set_ssh_keys_plugin.execute,
                              mock_service, fake_shared_data)
        else:
            with mock.patch('cloudbaseinit.plugins.common.sshpublickeys'
                            '.open',
                            mock.mock_open(), create=True):
                response = self._set_ssh_keys_plugin.execute(mock_service,
                                                             fake_shared_data)
                mock_service.get_public_keys.assert_called_with()
                mock_osutils.get_user_home.assert_called_with(
                    fake_username)
                self.assertEqual(2, mock_os_path.join.call_count)
                mock_os_makedirs.assert_called_once_with(mock_os_path.join())

                self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute_with_user_home(self):
        fake_user_home = os.path.join('fake', 'home')
        self._test_execute(user_home=fake_user_home)

    def test_execute_with_no_user_home(self):
        self._test_execute(user_home=None)

    def test_no_public_keys(self):
        mock_service = mock.Mock()
        mock_service.get_public_keys.return_value = None

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'sshpublickeys') as snatcher:
            self._set_ssh_keys_plugin.execute(mock_service, {})

        expected_logging = ['Public keys not found in metadata']
        self.assertEqual(expected_logging, snatcher.output)

    def test_execute_with_user_provided_by_metadata(self):
        fake_user_home = os.path.join('fake', 'home')
        self._test_execute(user_home=fake_user_home,
                           metadata_provided_username=True)
