# Copyright 2017 Cloudbase Solutions Srl
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

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from six.moves.urllib import error

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


CONF = cloudbaseinit_conf.CONF
BASE_MODULE_PATH = ("cloudbaseinit.metadata.services.base."
                    "BaseHTTPMetadataService")
MODULE_PATH = "cloudbaseinit.metadata.services.packet"


class PacketServiceTest(unittest.TestCase):

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

        self._packet_module = importlib.import_module(MODULE_PATH)
        self._packet_service = self._packet_module.PacketService()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @mock.patch(MODULE_PATH + ".PacketService._get_cache_data")
    def test_get_meta_data(self, mock_get_cache_data):
        mock_get_cache_data.return_value = '{"fake": "data"}'
        response = self._packet_service._get_meta_data()
        mock_get_cache_data.assert_called_with("metadata", decode=True)
        self.assertEqual({"fake": "data"}, response)

    @mock.patch(BASE_MODULE_PATH + ".load")
    @mock.patch(MODULE_PATH + ".PacketService._get_cache_data")
    def test_load(self, mock_get_cache_data, mock_load):
        mock_get_cache_data.return_value = '{"fake": "data"}'
        self.assertTrue(self._packet_service.load())

    @mock.patch(BASE_MODULE_PATH + ".load")
    @mock.patch(MODULE_PATH + ".PacketService._get_cache_data")
    def test_load_fails(self, mock_get_cache_data, mock_load):
        with testutils.LogSnatcher(MODULE_PATH) as snatcher:
            self.assertFalse(self._packet_service.load())
        self.assertEqual(snatcher.output,
                         ['Metadata not found at URL \'%s\'' %
                          CONF.packet.metadata_base_url])

    @mock.patch(MODULE_PATH + ".PacketService._get_meta_data")
    def test_get_instance_id(self, mock_get_meta_data):
        response = self._packet_service.get_instance_id()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('id')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch(MODULE_PATH +
                ".PacketService._get_meta_data")
    def test_get_host_name(self, mock_get_meta_data):
        response = self._packet_service.get_host_name()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('hostname')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch(MODULE_PATH +
                ".PacketService._get_meta_data")
    def _test_get_public_keys(self, mock_get_meta_data,
                              public_keys):
        mock_get_meta_data.return_value = {
            "ssh_keys": public_keys
        }
        response = self._packet_service.get_public_keys()
        mock_get_meta_data.assert_called_once_with()

        if public_keys:
            public_keys = list(set((key.strip() for key in public_keys)))
        else:
            public_keys = []

        self.assertEqual(sorted(public_keys),
                         sorted(response))

    def test_get_public_keys(self):
        self._test_get_public_keys(public_keys=["fake keys"] * 3)

    def test_get_public_keys_empty(self):
        self._test_get_public_keys(public_keys=None)

    @mock.patch(MODULE_PATH +
                ".PacketService._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._packet_service.get_user_data()
        mock_get_cache_data.assert_called_once_with("userdata")
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch(MODULE_PATH +
                ".PacketService._get_meta_data")
    def test_get_phone_home_url(self, mock_get_meta_data):
        fake_phone_url = 'fake_phone_url'
        mock_get_meta_data.return_value = {
            "phone_home_url": fake_phone_url
        }
        response = self._packet_service._get_phone_home_url()

        self.assertEqual(response, fake_phone_url)

    def test_can_post_password(self):
        self.assertEqual(self._packet_service.can_post_password,
                         True)

    @mock.patch(MODULE_PATH +
                ".PacketService._get_phone_home_url")
    @mock.patch(MODULE_PATH +
                ".PacketService._get_cache_data")
    def test_get_user_pwd_encryption_key(self, mock_get_cache_data,
                                         mock_get_phone_url):
        fake_phone_url = 'fake_phone_url'
        user_pwd_encryption_key = 'fake_key'

        mock_get_cache_data.return_value = user_pwd_encryption_key
        mock_get_phone_url.return_value = fake_phone_url

        response = self._packet_service.get_user_pwd_encryption_key()
        mock_get_phone_url.assert_called_once()
        mock_get_cache_data.assert_called_once_with(
            "%s/%s" % (fake_phone_url, 'key'), decode=True)

        self.assertEqual(response, user_pwd_encryption_key)

    @mock.patch('time.sleep')
    @mock.patch(MODULE_PATH +
                ".PacketService._get_phone_home_url")
    @mock.patch(MODULE_PATH +
                ".PacketService._http_request")
    def _test_post_password(self, mock_http_request,
                            mock_get_phone_url, mock_sleep, fail=False):
        fake_phone_url = 'fake_phone_url'
        fake_response = 'fake_response'
        fake_encoded_password = b'fake_password'

        if fail:
            mock_http_request.side_effect = (
                error.HTTPError(401, "invalid", {}, 0, 0))
            with self.assertRaises(exception.MetadataEndpointException):
                self._packet_service.post_password(fake_encoded_password)
        else:
            mock_http_request.return_value = fake_response
            mock_get_phone_url.return_value = fake_phone_url

            response = self._packet_service.post_password(
                fake_encoded_password)
            mock_get_phone_url.assert_called_once()
            mock_http_request.assert_called_once_with(
                data='{"password": "fake_password"}',
                url=fake_phone_url)

            self.assertEqual(response, fake_response)

    def test_post_password(self):
        self._test_post_password()

    def test_post_password_with_failure(self):
        self._test_post_password(fail=True)

    @mock.patch('time.sleep')
    @mock.patch(MODULE_PATH +
                ".PacketService._get_phone_home_url")
    @mock.patch(MODULE_PATH +
                ".PacketService._http_request")
    def _test_provisioning_completed(self, mock_http_request,
                                     mock_get_phone_url, mock_sleep,
                                     fail=False):
        fake_phone_url = 'fake_phone_url'
        fake_response = 'fake_response'

        if fail:
            mock_http_request.side_effect = (
                error.HTTPError(401, "invalid", {}, 0, 0))
            with self.assertRaises(exception.MetadataEndpointException):
                self._packet_service.provisioning_completed()
        else:
            mock_http_request.return_value = fake_response
            mock_get_phone_url.return_value = fake_phone_url

            response = self._packet_service.provisioning_completed()
            mock_get_phone_url.assert_called_once()
            mock_http_request.assert_called_once_with(
                url=fake_phone_url,
                method="post")

            self.assertEqual(response, fake_response)

    def test_provisioning_completed(self):
        self._test_provisioning_completed()

    def test_provisioning_completed_with_failure(self):
        self._test_provisioning_completed(fail=True)
