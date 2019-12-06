# Copyright 2020 Cloudbase Solutions Srl
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

import ddt
import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.tests import testutils


CONF = cloudbaseinit_conf.CONF
BASE_MODULE_PATH = ("cloudbaseinit.metadata.services.base."
                    "BaseHTTPMetadataService")
MODULE_PATH = "cloudbaseinit.metadata.services.gceservice"


@ddt.ddt
class GCEServiceTest(unittest.TestCase):

    def setUp(self):
        self._win32com_mock = mock.MagicMock()
        self._ctypes_mock = mock.MagicMock()
        self._ctypes_util_mock = mock.MagicMock()
        self._win32com_client_mock = mock.MagicMock()
        self._pywintypes_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'win32com': self._win32com_mock,
             'ctypes': self._ctypes_mock,
             'ctypes.util': self._ctypes_util_mock,
             'win32com.client': self._win32com_client_mock,
             'pywintypes': self._pywintypes_mock})
        self._module_patcher.start()
        self.addCleanup(self._module_patcher.stop)

        self._module = importlib.import_module(MODULE_PATH)
        self._service = self._module.GCEService()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @mock.patch(MODULE_PATH + ".GCEService._get_cache_data")
    def test_get_host_name(self, mock_get_cache_data):
        response = self._service.get_host_name()
        mock_get_cache_data.assert_called_once_with(
            'instance/name', decode=True)
        self.assertEqual(mock_get_cache_data.return_value,
                         response)

    @mock.patch(MODULE_PATH + ".GCEService._get_cache_data")
    def test_get_instance_id(self, mock_get_cache_data):
        response = self._service.get_instance_id()
        mock_get_cache_data.assert_called_once_with(
            'instance/id', decode=True)
        self.assertEqual(mock_get_cache_data.return_value,
                         response)

    @mock.patch(MODULE_PATH + ".GCEService._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._service.get_user_data()
        userdata_key = "%s/user-data" % self._module.MD_INSTANCE_ATTR
        userdata_enc_key = (
            "%s/user-data-encoding" % self._module.MD_INSTANCE_ATTR)
        mock_calls = [mock.call(userdata_key),
                      mock.call(userdata_enc_key, decode=True)]
        mock_get_cache_data.assert_has_calls(mock_calls)
        self.assertEqual(mock_get_cache_data.return_value,
                         response)

    @mock.patch(MODULE_PATH + ".GCEService._get_cache_data")
    def test_get_user_data_b64(self, mock_get_cache_data):
        user_data = b'fake userdata'
        user_data_b64 = 'ZmFrZSB1c2VyZGF0YQ=='
        userdata_key = "%s/user-data" % self._module.MD_INSTANCE_ATTR
        userdata_enc_key = (
            "%s/user-data-encoding" % self._module.MD_INSTANCE_ATTR)

        def _get_cache_data_side_effect(*args, **kwargs):
            if args[0] == ("%s/user-data" % self._module.MD_INSTANCE_ATTR):
                return user_data_b64
            return 'base64'
        mock_get_cache_data.side_effect = _get_cache_data_side_effect

        response = self._service.get_user_data()

        mock_calls = [mock.call(userdata_key),
                      mock.call(userdata_enc_key, decode=True)]
        mock_get_cache_data.assert_has_calls(mock_calls)
        self.assertEqual(response, user_data)

    @mock.patch(MODULE_PATH + ".GCEService._get_cache_data")
    @mock.patch(MODULE_PATH + ".GCEService._get_ssh_keys")
    @mock.patch(MODULE_PATH + ".GCEService._parse_gce_ssh_key")
    def _test_get_public_keys_block_project(self, mock_parse_keys,
                                            mock_get_ssh_keys,
                                            mock_cache_data,
                                            cache_data_result=False):
        expected_response = []

        if cache_data_result:
            second_call_get_ssh = [
                '%s/ssh-keys' % self._module.MD_INSTANCE_ATTR,
                '%s/ssh-keys' % self._module.MD_PROJECT_ATTR]
            mock_cache_data.return_value = 'false'
        else:
            second_call_get_ssh = [
                '%s/ssh-keys' % self._module.MD_INSTANCE_ATTR]
            mock_cache_data.return_value = 'true'
        mock_get_ssh_keys.return_value = []
        response = self._service.get_public_keys()
        mock_calls = [mock.call(second_call_get_ssh)]
        mock_get_ssh_keys.assert_has_calls(mock_calls)

        self.assertEqual(mock_parse_keys.call_count, 0)
        self.assertEqual(response, expected_response)

    def test_get_public_keys_block_project_check(self):
        self._test_get_public_keys_block_project(cache_data_result=False)

    def test_get_public_keys_block_project(self):
        self._test_get_public_keys_block_project(cache_data_result=True)

    @mock.patch(MODULE_PATH + ".GCEService._get_cache_data")
    def test__get_ssh_keys(self, mock_get_cache_data):
        fake_key = 'fake key'
        expected_response = [fake_key] * 3
        key_locations = ['location'] * 3
        mock_get_cache_data.return_value = fake_key
        response = self._service._get_ssh_keys(key_locations)
        self.assertEqual(response, expected_response)

    @ddt.data((None, True),
              ('not a date', True),
              ('2018-12-04T20:12:00+0000', False))
    @ddt.unpack
    def test__is_ssh_key_valid(self, expire_on, expected_response):
        response = self._service._is_ssh_key_valid(expire_on)
        self.assertEqual(response, expected_response)

    @ddt.data((None, None),
              ('ssh invalid', None),
              ('notadmin:ssh key notadmin', None),
              ('Admin:ssh key Admin', 'ssh key Admin'),
              ('ssh key google-ssh', None),
              ('Admin:s k google-ssh {"userName":"Admin",'
               '"expireOn":"1018-12-04T20:12:00+0000"}',
               None),
              ('Admin:s k google-ssh {"userName":"b",'
               '"expireOn":"3018-12-04T20:12:00+0000"}',
               None),
              ('Admin:s k google-ssh {"userName":"Admin",'
               '"expireOn":"3018-12-04T20:12:00+0000"}',
               's k Admin'))
    @ddt.unpack
    def test__parse_gce_ssh_key(self, raw_ssh_key, expected_response):
        response = self._service._parse_gce_ssh_key(raw_ssh_key)
        self.assertEqual(response, expected_response)
