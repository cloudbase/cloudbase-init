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
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from six.moves.urllib import error

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import httpservice

CONF = cloudbaseinit_conf.CONF


class HttpServiceTest(unittest.TestCase):

    def setUp(self):
        self._httpservice = httpservice.HttpService()

    @mock.patch('cloudbaseinit.utils.network.check_metadata_ip_route')
    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._get_meta_data')
    def _test_load(self, mock_get_meta_data, mock_check_metadata_ip_route,
                   side_effect):
        mock_get_meta_data.side_effect = [side_effect]
        response = self._httpservice.load()
        mock_check_metadata_ip_route.assert_called_once_with(
            CONF.openstack.metadata_base_url)
        mock_get_meta_data.assert_called_once_with()
        if side_effect:
            self.assertFalse(response)
        else:
            self.assertTrue(response)

    def test_load(self):
        self._test_load(side_effect=None)

    def test_load_exception(self):
        self._test_load(side_effect=Exception)

    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._http_request')
    def test_post_data(self, mock_http_request):
        fake_path = os.path.join('fake', 'path')
        fake_data = 'fake data'
        mock_data = mock.MagicMock()
        mock_http_request.return_value = mock_data

        response = self._httpservice._post_data(fake_path, fake_data)
        mock_http_request.assert_called_once_with(fake_path, data=fake_data)
        self.assertTrue(response)

    def test_get_password_path(self):
        response = self._httpservice._get_password_path()
        self.assertEqual('openstack/%s/password' %
                         self._httpservice._POST_PASSWORD_MD_VER, response)

    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._get_meta_data')
    def test_can_post_password(self, mock_get_meta_data):
        self.assertTrue(self._httpservice.can_post_password)
        mock_get_meta_data.side_effect = base.NotExistingMetadataException
        self.assertFalse(self._httpservice.can_post_password)

    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._get_password_path')
    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._post_data')
    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._exec_with_retry')
    def _test_post_password(self, mock_exec_with_retry, mock_post_data,
                            mock_get_password_path, ret_val):
        mock_exec_with_retry.side_effect = [ret_val]
        if isinstance(ret_val, error.HTTPError) and ret_val.code == 409:
            response = self._httpservice.post_password(
                enc_password_b64='fake')
            self.assertEqual(response, False)
        elif isinstance(ret_val, error.HTTPError) and ret_val.code != 409:
            self.assertRaises(error.HTTPError,
                              self._httpservice.post_password, 'fake')
        else:
            response = self._httpservice.post_password(
                enc_password_b64='fake')
            mock_get_password_path.assert_called_once_with()
            self.assertEqual(ret_val, response)

    @mock.patch('cloudbaseinit.metadata.services.base.BaseHTTPMetadataService'
                '._get_data')
    def test_is_password_set(self, mock_get_data):
        mock_get_data.return_value = "fake-data"
        res = self._httpservice.is_password_set
        self.assertTrue(res)

    def test_post_password(self):
        self._test_post_password(ret_val='fake return')

    def test_post_password_HTTPError_409(self):
        err = error.HTTPError("http://169.254.169.254/", 409,
                              'test error 409', {}, None)
        self._test_post_password(ret_val=err)

    def test_post_password_other_HTTPError(self):
        err = error.HTTPError("http://169.254.169.254/", 404,
                              'test error 404', {}, None)
        self._test_post_password(ret_val=err)
