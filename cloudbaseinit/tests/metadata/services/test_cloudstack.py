# Copyright 2014 Cloudbase Solutions Srl
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

import socket
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo.config import cfg
from six.moves import urllib

from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import cloudstack
from cloudbaseinit.tests import testutils

CONF = cfg.CONF


class CloudStackTest(unittest.TestCase):

    def setUp(self):
        CONF.set_override('retry_count_interval', 0)
        self._service = self._get_service()
        self._service._metadata_uri = "http://10.1.1.1/latest/meta-data/"

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _get_service(self, mock_os_util):
        return cloudstack.CloudStack()

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._http_request')
    def test_test_api(self, mock_http_request):
        url = '127.0.0.1'
        mock_http_request.side_effect = [
            '200 OK. Successfully!',    # Request to Web Service
            'service-offering',         # Response for get_data
            urllib.error.HTTPError(url=url, code=404, hdrs={}, fp=None,
                                   msg='Testing 404 Not Found.'),
            urllib.error.HTTPError(url=url, code=427, hdrs={}, fp=None,
                                   msg='Testing 429 Too Many Requests.'),
            base.NotExistingMetadataException(),
            socket.error,
        ]

        self.assertTrue(self._service._test_api(url))
        for _ in range(4):
            self.assertFalse(self._service._test_api(url))

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._test_api')
    def test_load(self, mock_test_api, mock_os_util):
        self._service.osutils.get_dhcp_hosts_in_use = mock.Mock()
        self._service.osutils.get_dhcp_hosts_in_use.side_effect = [
            [(mock.sentinel.mac_address, '10.10.0.1'),
             (mock.sentinel.mac_address, '10.10.0.2'),
             (mock.sentinel.mac_address, '10.10.0.3')]
        ]
        mock_test_api.side_effect = [False, False, False, True]

        self.assertTrue(self._service.load())
        self.assertEqual(4, mock_test_api.call_count)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._test_api')
    def test_load_default(self, mock_test_api):
        mock_test_api.side_effect = [True]
        self._service._test_api = mock_test_api

        self.assertTrue(self._service.load())
        mock_test_api.assert_called_once_with(CONF.cloudstack_metadata_ip)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._test_api')
    def test_load_fail(self, mock_test_api, mock_os_util):
        self._service.osutils.get_dhcp_hosts_in_use.side_effect = [None]
        mock_test_api.side_effect = [False]

        self.assertFalse(self._service.load())  # No DHCP server was found.
        mock_test_api.assert_called_once_with(CONF.cloudstack_metadata_ip)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._test_api')
    def test_load_no_service(self, mock_test_api, mock_os_util):
        self._service.osutils.get_dhcp_hosts_in_use = mock.Mock()
        self._service.osutils.get_dhcp_hosts_in_use.side_effect = [
            [(mock.sentinel.mac_address, CONF.cloudstack_metadata_ip)]
        ]
        mock_test_api.side_effect = [False, False]

        # No service
        self.assertFalse(self._service.load())
        self.assertEqual(2, mock_test_api.call_count)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._http_request')
    def test_get_data(self, mock_http_request):
        metadata = 'service-offering'
        mock_http_request.side_effect = [
            mock.sentinel.ok,
            urllib.error.HTTPError(url=metadata, code=404, hdrs={}, fp=None,
                                   msg='Testing 404 Not Found.'),
            urllib.error.HTTPError(url=metadata, code=427, hdrs={}, fp=None,
                                   msg='Testing 429 Too Many Requests.')
        ]

        for status in (200, 404, 427):
            if status == 200:
                response = self._service._get_data(metadata)
                self.assertEqual(mock.sentinel.ok, response)
            elif status == 404:
                self.assertRaises(base.NotExistingMetadataException,
                                  self._service._get_data, metadata)
            else:
                self.assertRaises(urllib.error.HTTPError,
                                  self._service._get_data, metadata)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._get_data')
    def test_get_cache_data(self, mock_get_data):
        side_effect = mock.sentinel.metadata
        mock_get_data.side_effect = [side_effect]
        self._service._get_data = mock_get_data

        response = self._service._get_cache_data(mock.sentinel.metadata)
        self.assertEqual(mock.sentinel.metadata, response)
        mock_get_data.assert_called_once_with(mock.sentinel.metadata)
        mock_get_data.reset_mock()

        response = self._service._get_cache_data(mock.sentinel.metadata)
        self.assertEqual(mock.sentinel.metadata, response)
        self.assertEqual(0, mock_get_data.call_count)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._get_cache_data')
    def _test_cache_response(self, mock_get_cache_data, method, metadata):
        mock_get_cache_data.side_effect = [mock.sentinel.response]
        response = method()

        self.assertEqual(mock.sentinel.response, response)
        mock_get_cache_data.assert_called_once_with(metadata)

    def test_get_instance_id(self):
        self._test_cache_response(method=self._service.get_instance_id,
                                  metadata='instance-id')

    def test_get_host_name(self):
        self._test_cache_response(method=self._service.get_host_name,
                                  metadata='local-hostname')

    def test_get_user_data(self):
        self._test_cache_response(method=self._service.get_user_data,
                                  metadata='../user-data')

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._get_cache_data')
    def test_get_public_keys(self, mock_get_cache_data):
        mock_get_cache_data.side_effect = [
            "ssh-rsa AAAA\nssh-rsa BBBB\nssh-rsa CCCC",
            "\n\nssh-rsa AAAA\n\nssh-rsa BBBB\n\nssh-rsa CCCC",
            " \n \n ssh-rsa AAAA \n \n ssh-rsa BBBB \n \n ssh-rsa CCCC",
            " ", "\n", " \n "
        ]
        for _ in range(3):
            response = self._service.get_public_keys()
            self.assertEqual(["ssh-rsa AAAA", "ssh-rsa BBBB", "ssh-rsa CCCC"],
                             response)

        for _ in range(3):
            response = self._service.get_public_keys()
            self.assertEqual([], response)

    @mock.patch('six.moves.urllib.request')
    def test__http_request(self, mock_urllib_request):
        mock_urllib_request.Request.return_value = mock.sentinel.request
        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'cloudstack') as snatcher:
            self._service._http_request(mock.sentinel.url)

        expected_logging = [
            'Getting metadata from:  %s' % mock.sentinel.url,
        ]
        mock_urllib_request.Request.assert_called_once_with(
            mock.sentinel.url)
        mock_urllib_request.urlopen.assert_called_once_with(
            mock.sentinel.request)
        mock_urlopen = mock_urllib_request.urlopen.return_value
        mock_urlopen.read.assert_called_once_with()
        self.assertEqual(expected_logging, snatcher.output)
