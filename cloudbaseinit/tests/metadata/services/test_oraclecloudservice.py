# Copyright (c) 2026, Oracle and/or its affiliates.
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
from cloudbaseinit.metadata.services import oraclecloudservice
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class OracleCloudServiceTest(unittest.TestCase):

    def setUp(self):
        self._service = oraclecloudservice.OracleCloudService()

    @mock.patch('cloudbaseinit.utils.network.check_metadata_ip_route')
    @mock.patch('cloudbaseinit.metadata.services.oraclecloudservice.'
                'OracleCloudService.get_instance_id')
    def _test_load(self, mock_get_instance_id, mock_check_metadata_ip_route,
                   side_effect):
        mock_get_instance_id.side_effect = [side_effect]
        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'oraclecloudservice'):
            response = self._service.load()

        mock_check_metadata_ip_route.assert_called_once_with(
            CONF.oraclecloud.metadata_base_url)
        mock_get_instance_id.assert_called_once_with()
        if side_effect is Exception:
            self.assertFalse(response)
        else:
            self.assertTrue(response)

    def test_load(self):
        self._test_load(side_effect=None)

    def test_load_exception(self):
        self._test_load(side_effect=Exception)

    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseHTTPMetadataService._http_request')
    def test_http_request(self, mock_http_request):
        headers = {'Test-Header': 'test-value'}
        expected_headers = dict(headers)
        expected_headers.update(self._service._headers)

        response = self._service._http_request(
            mock.sentinel.url, data=mock.sentinel.data, headers=headers,
            method=mock.sentinel.method)

        mock_http_request.assert_called_once_with(
            mock.sentinel.url, mock.sentinel.data, expected_headers,
            mock.sentinel.method)
        self.assertEqual(mock_http_request.return_value, response)
        self.assertEqual({'Test-Header': 'test-value'}, headers)

    @mock.patch('cloudbaseinit.metadata.services.oraclecloudservice.'
                'OracleCloudService._get_cache_data')
    def test_get_instance_id(self, mock_get_cache_data):
        mock_get_cache_data.return_value = 'test-instance-id'
        response = self._service.get_instance_id()
        mock_get_cache_data.assert_called_once_with(
            'opc/%s/instance/id' % self._service._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch('cloudbaseinit.metadata.services.oraclecloudservice.'
                'OracleCloudService._get_cache_data')
    def test_get_user_data(self, mock_get_cache_data):
        mock_get_cache_data.return_value = (
            'VGVzdGluZyBvdXIgY29kZSBpcyBnb29kCg==')
        response = self._service.get_user_data()
        mock_get_cache_data.assert_called_once_with(
            'opc/%s/instance/metadata/user_data' %
            self._service._metadata_version)
        self.assertEqual(response.decode(), "Testing our code is good\n")

    @mock.patch('cloudbaseinit.metadata.services.oraclecloudservice.'
                'OracleCloudService._get_cache_data')
    def test_get_host_name(self, mock_get_cache_data):
        mock_get_cache_data.return_value = 'test-hostname'
        response = self._service.get_host_name()
        mock_get_cache_data.assert_called_once_with(
            'opc/%s/instance/hostname' % self._service._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)
