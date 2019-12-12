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

import mock
import requests
import unittest

from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base


class FakeService(base.BaseMetadataService):
    def _get_data(self):
        return (b'\x1f\x8b\x08\x00\x93\x90\xf2U\x02'
                b'\xff\xcbOSH\xce/-*NU\xc8,Q(\xcf/\xca.'
                b'\x06\x00\x12:\xf6a\x12\x00\x00\x00')

    def get_user_data(self):
        return self._get_data()


class TestBase(unittest.TestCase):

    def setUp(self):
        self._service = FakeService()

    def test_get_decoded_user_data(self):
        userdata = self._service.get_decoded_user_data()
        self.assertEqual(b"of course it works", userdata)

    def test_get_name(self):
        self.assertEqual(self._service.get_name(), 'FakeService')

    def test_can_post_password(self):
        self.assertFalse(self._service.can_post_password)

    def test_is_password_set(self):
        self.assertFalse(self._service.is_password_set)

    def test_can_update_password(self):
        self.assertFalse(self._service.can_update_password)

    def test_is_password_changed(self):
        self.assertFalse(self._service.is_password_changed())

    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseMetadataService.get_public_keys')
    def test_get_user_pwd_encryption_key(self, mock_get_public_keys):
        mock_get_public_keys.return_value = ['fake', 'keys']
        result = self._service.get_user_pwd_encryption_key()
        self.assertEqual(result, mock_get_public_keys.return_value[0])

    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseMetadataService.get_public_keys')
    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseMetadataService.get_host_name')
    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseMetadataService.get_instance_id')
    def test_get_instance_data(self, mock_instance_id, mock_hostname,
                               mock_public_keys):
        fake_instance_id = 'id'
        mock_instance_id.return_value = fake_instance_id
        fake_hostname = 'host'
        mock_hostname.return_value = fake_hostname
        fake_keys = ['ssh1', 'ssh2']
        mock_public_keys.return_value = fake_keys

        expected_response = {
            'v1': {
                "instance_id": fake_instance_id,
                "local_hostname": fake_hostname,
                "public_ssh_keys": fake_keys
            },
            'ds': {
                'meta_data': {
                    "instance_id": fake_instance_id,
                    "local_hostname": fake_hostname,
                    "public_ssh_keys": fake_keys,
                    "hostname": fake_hostname
                },
            }
        }
        self.assertEqual(expected_response, self._service.get_instance_data())


class TestBaseHTTPMetadataService(unittest.TestCase):

    def setUp(self):
        self._mock_base_url = "http://metadata.mock/"
        self._service = base.BaseHTTPMetadataService("http://metadata.mock/")

    def _test_verify_https_request(self, https_ca_bundle=None):
        mock_service = base.BaseHTTPMetadataService(
            base_url=mock.sentinel.url,
            https_allow_insecure=mock.sentinel.allow_insecure,
            https_ca_bundle=https_ca_bundle)

        response = mock_service._verify_https_request()

        if not https_ca_bundle:
            self.assertTrue(mock.sentinel.allow_insecure)
        else:
            self.assertEqual(response, https_ca_bundle)

    def test_verify_https_request(self):
        self._test_verify_https_request()

    def test_verify_https_request_with_ca_bundle(self):
        self._test_verify_https_request(https_ca_bundle="/path/to/resource")

    @mock.patch('requests.request')
    @mock.patch("cloudbaseinit.metadata.services.base.BaseHTTPMetadataService."
                "_verify_https_request")
    def _test_http_request(self, mock_verify, mock_request, mock_url,
                           mock_data=None, mock_headers=None, mock_method=None,
                           expected_method='GET'):
        if not mock_url.startswith('http'):
            mock_url = requests.compat.urljoin(self._mock_base_url, mock_url)

        mock_response = mock.Mock()
        mock_response_status = mock.Mock()
        mock_response.raise_for_status = mock_response_status
        mock_response.content = mock.sentinel.content
        mock_request.return_value = mock_response

        mock_verify.return_value = mock.sentinel.verify

        response = self._service._http_request(url=mock_url, data=mock_data,
                                               headers=mock_headers,
                                               method=mock_method)

        mock_request.assert_called_once_with(
            method=expected_method, url=mock_url, data=mock_data,
            headers=mock_headers, verify=mock.sentinel.verify)

        mock_response_status.assert_called_once_with()
        self.assertEqual(response, mock.sentinel.content)

    def test_http_get_request(self):
        self._test_http_request(mock_url="/path/to/resource",
                                mock_data=None,
                                mock_headers={}, expected_method="GET")

    def test_http_post_request(self):
        self._test_http_request(mock_url="/path/to/resource",
                                mock_data={"X-Cloudbase-Init", True},
                                mock_headers={}, expected_method="POST")

    def test_http_force_post_request(self):
        self._test_http_request(mock_url="/path/to/resource",
                                mock_data=None, mock_headers={},
                                mock_method="post", expected_method="POST")

    def test_http_force_get_request(self):
        self._test_http_request(mock_url="/path/to/resource",
                                mock_data={"X-Cloudbase-Init", True},
                                mock_headers={}, mock_method="get",
                                expected_method="GET")

    def test_http_force_head_request(self):
        self._test_http_request(mock_url="/path/to/resource",
                                mock_headers={}, mock_method="head",
                                expected_method="HEAD")

    @mock.patch('requests.compat.urljoin')
    @mock.patch("cloudbaseinit.metadata.services.base."
                "BaseHTTPMetadataService._http_request")
    def _test_get_data(self, mock_http_request, mock_urljoin,
                       expected_response, expected_value):
        fake_base_url = mock.Mock()
        http_service = base.BaseHTTPMetadataService(fake_base_url)
        mock_request = mock.Mock()
        mock_urljoin.return_value = 'some_url'
        mock_http_request.side_effect = [expected_response]
        if expected_value:
            self.assertRaises(expected_value, http_service._get_data,
                              mock_request)
        else:
            response = http_service._get_data(mock_request)
            self.assertEqual(expected_response, response)

    def test_get_response(self):
        self._test_get_data(expected_response='fake response',
                            expected_value=False)

    def test_get_response_not_found(self):
        fake_response = mock.Mock()
        fake_response.status_code = 404
        http_error = requests.HTTPError()
        http_error.response = fake_response
        http_error.message = mock.Mock()
        self._test_get_data(expected_response=http_error,
                            expected_value=base.NotExistingMetadataException)

    def test_get_response_http_error(self):
        fake_response = mock.Mock()
        fake_response.status_code = 400
        http_error = requests.HTTPError()
        http_error.response = fake_response
        self._test_get_data(expected_response=http_error,
                            expected_value=requests.HTTPError)

    def test_get_response_ssl_error(self):
        ssl_error = requests.exceptions.SSLError()
        self._test_get_data(expected_response=ssl_error,
                            expected_value=exception.CertificateVerifyFailed)


class TestEmptyMetadataService(unittest.TestCase):

    def setUp(self):
        self._service = base.EmptyMetadataService()

    def test_get_name(self):
        self.assertEqual(self._service.get_name(), 'EmptyMetadataService')

    def test__get_data(self):
        self.assertFalse(self._service._get_data('fake_path'))

    def test_get_admin_username(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_admin_username)

    def test_get_admin_password(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_admin_password)

    def test_is_password_changed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.is_password_changed)
