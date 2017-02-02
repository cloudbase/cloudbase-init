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

from cloudbaseinit import constant
from cloudbaseinit.plugins.windows import sanpolicy
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils.windows.storage import base as storage_base


class SANPolicyPluginTests(unittest.TestCase):

    def setUp(self):
        self._san_policy = sanpolicy.SANPolicyPlugin()
        self._san_policy_map = {
            constant.SAN_POLICY_ONLINE_STR: storage_base.SAN_POLICY_ONLINE,
            constant.SAN_POLICY_OFFLINE_STR: storage_base.SAN_POLICY_OFFLINE,
            constant.SAN_POLICY_OFFLINE_SHARED_STR:
            storage_base.SAN_POLICY_OFFLINE_SHARED,
        }

    def test_get_os_requirements(self):
        response = self._san_policy.get_os_requirements()

        self.assertEqual(response, ('win32', (6, 1)))

    @mock.patch('cloudbaseinit.utils.windows.storage.factory'
                '.get_storage_manager')
    def _test_set_policy(self, policy, mock_storage_factory):
        mock_storage_manager = mock.MagicMock()
        mock_storage_manager.get_san_policy.return_value = "fake policy"
        mock_storage_factory.return_value = mock_storage_manager

        with testutils.ConfPatcher('san_policy', policy):
            self._san_policy.execute(None, "")

            mock_storage_manager.set_san_policy.assert_called_once_with(
                self._san_policy_map[policy])

    @mock.patch('cloudbaseinit.utils.windows.storage.factory'
                '.get_storage_manager')
    def _test_set_policy_already_set(self, policy, mock_storage_factory):
        mock_storage_manager = mock.MagicMock()
        san_policy = self._san_policy_map[policy]
        mock_storage_manager.get_san_policy.return_value = san_policy
        mock_storage_factory.return_value = mock_storage_manager

        with testutils.ConfPatcher('san_policy', policy):
            self._san_policy.execute(None, "")

            self.assertEqual(mock_storage_manager.call_count, 0)

    def test_set_policy_online(self):
        self._test_set_policy(constant.SAN_POLICY_ONLINE_STR)

    def test_set_policy_offline(self):
        self._test_set_policy(constant.SAN_POLICY_OFFLINE_STR)

    def test_set_policy_offline_shared(self):
        self._test_set_policy(constant.SAN_POLICY_OFFLINE_SHARED_STR)

    def test_set_policy_online_already_set(self):
        self._test_set_policy_already_set(constant.SAN_POLICY_ONLINE_STR)

    def test_set_policy_offline_already_set(self):
        self._test_set_policy_already_set(constant.SAN_POLICY_OFFLINE_STR)

    def test_set_policy_offline_shared_already_set(self):
        self._test_set_policy_already_set(
            constant.SAN_POLICY_OFFLINE_SHARED_STR)

    @mock.patch('cloudbaseinit.utils.windows.storage.factory'
                '.get_storage_manager')
    def test_san_policy_not_set(self, mock_storage_factory):
        self._san_policy.execute(None, "")

        self.assertEqual(mock_storage_factory.call_count, 0)
