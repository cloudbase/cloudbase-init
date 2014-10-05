# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import mock
import os
import posixpath
import sys
import unittest

from oslo.config import cfg
from six.moves.urllib import error

from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import x509constants

if sys.version_info < (3, 0):
    # TODO(alexpilotti) replace oauth with a Python 3 compatible module
    from cloudbaseinit.metadata.services import maasservice

CONF = cfg.CONF


class MaaSHttpServiceTest(unittest.TestCase):
    def setUp(self):
        if sys.version_info < (3, 0):
            self.mock_oauth = mock.MagicMock()
            maasservice.oauth = self.mock_oauth
            self._maasservice = maasservice.MaaSHttpService()
        else:
            self.skipTest("Python 3 is not yet supported for maasservice")

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_data")
    def _test_load(self, mock_get_data, ip):
        CONF.set_override('maas_metadata_url', ip)
        response = self._maasservice.load()
        if ip is not None:
            mock_get_data.assert_called_once_with(
                '%s/meta-data/' % self._maasservice._metadata_version)
            self.assertTrue(response)
        else:
            self.assertFalse(response)

    def test_load(self):
        self._test_load(ip='196.254.196.254')

    def test_load_no_ip(self):
        self._test_load(ip=None)

    @mock.patch('six.moves.urllib.request.urlopen')
    def _test_get_response(self, mock_urlopen, ret_val):
        mock_request = mock.MagicMock()
        mock_urlopen.side_effect = [ret_val]
        if isinstance(ret_val, error.HTTPError) and ret_val.code == 404:
            self.assertRaises(base.NotExistingMetadataException,
                              self._maasservice._get_response, mock_request)
        elif isinstance(ret_val, error.HTTPError) and ret_val.code != 404:
            self.assertRaises(error.HTTPError,
                              self._maasservice._get_response, mock_request)
        else:
            response = self._maasservice._get_response(req=mock_request)
            mock_urlopen.assert_called_once_with(mock_request)
            self.assertEqual(ret_val, response)

    def test_get_response(self):
        self._test_get_response(ret_val='fake response')

    def test_get_response_error_404(self):
        err = error.HTTPError("http://169.254.169.254/", 404,
                              'test error 404', {}, None)
        self._test_get_response(ret_val=err)

    def test_get_response_error_not_404(self):
        err = error.HTTPError("http://169.254.169.254/", 409,
                              'test other error', {}, None)
        self._test_get_response(ret_val=err)

    @mock.patch('time.time')
    def test_get_oauth_headers(self, mock_time):
        mock_token = mock.MagicMock()
        mock_consumer = mock.MagicMock()
        mock_req = mock.MagicMock()
        self.mock_oauth.OAuthConsumer.return_value = mock_consumer
        self.mock_oauth.OAuthToken.return_value = mock_token
        self.mock_oauth.OAuthRequest.return_value = mock_req
        mock_time.return_value = 0
        self.mock_oauth.generate_nonce.return_value = 'fake nounce'
        response = self._maasservice._get_oauth_headers(url='196.254.196.254')
        self.mock_oauth.OAuthConsumer.assert_called_once_with(
            CONF.maas_oauth_consumer_key, CONF.maas_oauth_consumer_secret)
        self.mock_oauth.OAuthToken.assert_called_once_with(
            CONF.maas_oauth_token_key, CONF.maas_oauth_token_secret)
        parameters = {'oauth_version': "1.0",
                      'oauth_nonce': 'fake nounce',
                      'oauth_timestamp': int(0),
                      'oauth_token': mock_token.key,
                      'oauth_consumer_key': mock_consumer.key}
        self.mock_oauth.OAuthRequest.assert_called_once_with(
            http_url='196.254.196.254', parameters=parameters)
        mock_req.sign_request.assert_called_once_with(
            self.mock_oauth.OAuthSignatureMethod_PLAINTEXT(), mock_consumer,
            mock_token)
        self.assertEqual(mock_req.to_header.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_oauth_headers")
    @mock.patch("six.moves.urllib.request.Request")
    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_response")
    def test_get_data(self, mock_get_response, mock_Request,
                      mock_get_oauth_headers):
        CONF.set_override('maas_metadata_url', '196.254.196.254')
        fake_path = os.path.join('fake', 'path')
        mock_get_oauth_headers.return_value = 'fake headers'
        response = self._maasservice._get_data(path=fake_path)
        norm_path = posixpath.join(CONF.maas_metadata_url, fake_path)
        mock_get_oauth_headers.assert_called_once_with(norm_path)
        mock_Request.assert_called_once_with(norm_path,
                                             headers='fake headers')
        mock_get_response.assert_called_once_with(mock_Request())
        self.assertEqual(mock_get_response.return_value.read.return_value,
                         response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_host_name(self, mock_get_cache_data):
        response = self._maasservice.get_host_name()
        mock_get_cache_data.assert_called_once_with(
            '%s/meta-data/local-hostname' %
            self._maasservice._metadata_version)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_instance_id(self, mock_get_cache_data):
        response = self._maasservice.get_instance_id()
        mock_get_cache_data.assert_called_once_with(
            '%s/meta-data/instance-id' % self._maasservice._metadata_version)
        self.assertEqual(mock_get_cache_data.return_value, response)

    def test_get_list_from_text(self):
        response = self._maasservice._get_list_from_text('fake:text', ':')
        self.assertEqual(['fake:', 'text:'], response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_list_from_text")
    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_public_keys(self, mock_get_cache_data,
                             mock_get_list_from_text):
        response = self._maasservice.get_public_keys()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/public-keys' % self._maasservice._metadata_version)
        mock_get_list_from_text.assert_called_once_with(mock_get_cache_data(),
                                                        "\n")
        self.assertEqual(mock_get_list_from_text.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_list_from_text")
    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_client_auth_certs(self, mock_get_cache_data,
                                   mock_get_list_from_text):
        response = self._maasservice.get_client_auth_certs()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/x509' % self._maasservice._metadata_version)
        mock_get_list_from_text.assert_called_once_with(
            mock_get_cache_data(), "%s\n" % x509constants.PEM_FOOTER)
        self.assertEqual(mock_get_list_from_text.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._maasservice.get_user_data()
        mock_get_cache_data.assert_called_once_with(
            '%s/user-data' %
            self._maasservice._metadata_version)
        self.assertEqual(mock_get_cache_data.return_value, response)
