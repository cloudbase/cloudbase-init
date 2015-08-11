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

import os
import posixpath
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo_config import cfg
from six.moves.urllib import error

from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import maasservice
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import x509constants


CONF = cfg.CONF


class MaaSHttpServiceTest(unittest.TestCase):

    def setUp(self):
        self._maasservice = maasservice.MaaSHttpService()

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def _test_load(self, mock_get_cache_data, ip, cache_data_fails=False):
        if cache_data_fails:
            mock_get_cache_data.side_effect = Exception

        with testutils.ConfPatcher('maas_metadata_url', ip):
            with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                       'maasservice') as snatcher:
                response = self._maasservice.load()

            if ip is not None:
                if not cache_data_fails:
                    mock_get_cache_data.assert_called_once_with(
                        '%s/meta-data/' % self._maasservice._metadata_version)
                    self.assertTrue(response)
                else:
                    expected_logging = 'Metadata not found at URL \'%s\'' % ip
                    self.assertEqual(expected_logging, snatcher.output[-1])
            else:
                self.assertFalse(response)

    def test_load(self):
        self._test_load(ip='196.254.196.254')

    def test_load_no_ip(self):
        self._test_load(ip=None)

    def test_load_get_cache_data_fails(self):
        self._test_load(ip='196.254.196.254', cache_data_fails=True)

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

    @testutils.ConfPatcher('maas_oauth_consumer_key', 'consumer_key')
    @testutils.ConfPatcher('maas_oauth_consumer_secret', 'consumer_secret')
    @testutils.ConfPatcher('maas_oauth_token_key', 'token_key')
    @testutils.ConfPatcher('maas_oauth_token_secret', 'token_secret')
    def test_get_oauth_headers(self):
        response = self._maasservice._get_oauth_headers(url='196.254.196.254')
        self.assertIsInstance(response, dict)
        self.assertIn('Authorization', response)

        auth = response['Authorization']
        self.assertTrue(auth.startswith('OAuth'))

        auth = auth[6:]
        parts = [item.strip() for item in auth.split(",")]
        auth_parts = dict(part.split("=") for part in parts)

        required_headers = {
            'oauth_token',
            'oauth_consumer_key',
            'oauth_signature',
        }
        self.assertTrue(required_headers.issubset(set(auth_parts)))
        self.assertEqual('"token_key"', auth_parts['oauth_token'])
        self.assertEqual('"consumer_key"', auth_parts['oauth_consumer_key'])
        self.assertEqual('"consumer_secret%26token_secret"',
                         auth_parts['oauth_signature'])

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_oauth_headers")
    @mock.patch("six.moves.urllib.request.Request")
    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_response")
    def test_get_data(self, mock_get_response, mock_Request,
                      mock_get_oauth_headers):
        with testutils.ConfPatcher('maas_metadata_url', '196.254.196.254'):
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
            self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_instance_id(self, mock_get_cache_data):
        response = self._maasservice.get_instance_id()
        mock_get_cache_data.assert_called_once_with(
            '%s/meta-data/instance-id' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_public_keys(self, mock_get_cache_data):
        public_keys = [
            "fake key 1",
            "fake key 2"
        ]
        public_key = "\n".join(public_keys) + "\n"
        mock_get_cache_data.return_value = public_key
        response = self._maasservice.get_public_keys()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/public-keys' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(public_keys, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_client_auth_certs(self, mock_get_cache_data):
        certs = [
            "{begin}\n{cert}\n{end}".format(
                begin=x509constants.PEM_HEADER,
                end=x509constants.PEM_FOOTER,
                cert=cert)
            for cert in ("first cert", "second cert")
        ]
        mock_get_cache_data.return_value = "\n".join(certs) + "\n"
        response = self._maasservice.get_client_auth_certs()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/x509' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(certs, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._maasservice.get_user_data()
        mock_get_cache_data.assert_called_once_with(
            '%s/user-data' %
            self._maasservice._metadata_version)
        self.assertEqual(mock_get_cache_data.return_value, response)
