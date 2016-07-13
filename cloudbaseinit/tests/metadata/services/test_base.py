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

    @mock.patch('requests.post')
    @mock.patch('requests.get')
    @mock.patch("cloudbaseinit.metadata.services.base.BaseHTTPMetadataService."
                "_verify_https_request")
    def _test_http_request(self, mock_verify, mock_get, mock_post,
                           mock_url, mock_data=None, mock_headers=None):
        if not mock_url.startswith('http'):
            mock_url = requests.compat.urljoin(self._mock_base_url, mock_url)

        mock_response = mock.Mock()
        mock_response_status = mock.Mock()
        mock_response.raise_for_status = mock_response_status
        mock_response.content = mock.sentinel.content

        mock_get.return_value = mock_response
        mock_post.return_value = mock_response
        mock_verify.return_value = mock.sentinel.verify

        response = self._service._http_request(url=mock_url, data=mock_data,
                                               headers=mock_headers)

        if mock_data:
            mock_post.assert_called_once_with(
                url=mock_url, data=mock_data, headers=mock_headers,
                verify=mock.sentinel.verify
            )
        else:
            mock_get.assert_called_once_with(
                url=mock_url, data=mock_data, headers=mock_headers,
                verify=mock.sentinel.verify
            )

        mock_response_status.assert_called_once_with()
        self.assertEqual(response, mock.sentinel.content)

    def test_http_get_request(self):
        self._test_http_request(mock_url="/path/to/resource",
                                mock_data=None,
                                mock_headers={})

    def test_http_post_request(self):
        self._test_http_request(mock_url="/path/to/resource",
                                mock_data={"X-Cloudbase-Init", True},
                                mock_headers={})

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
