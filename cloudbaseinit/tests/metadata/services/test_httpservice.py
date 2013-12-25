# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions Srl
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
import unittest
import urllib2

from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import httpservice
from cloudbaseinit.openstack.common import cfg

CONF = cfg.CONF


class HttpServiceTest(unittest.TestCase):
    def setUp(self):
        CONF.set_override('retry_count_interval', 0)
        self._httpservice = httpservice.HttpService()

    @mock.patch('cloudbaseinit.osutils.factory.OSUtilsFactory.get_os_utils')
    @mock.patch('urlparse.urlparse')
    def _test_check_metadata_ip_route(self, mock_urlparse, mock_get_os_utils,
                                      side_effect):
        mock_utils = mock.MagicMock()
        mock_split = mock.MagicMock()
        mock_get_os_utils.return_value = mock_utils
        mock_utils.check_os_version.return_value = True
        mock_urlparse().netloc.split.return_value = mock_split
        mock_split[0].startswith.return_value = True
        mock_utils.check_static_route_exists.return_value = False
        mock_utils.get_default_gateway.return_value = (1, '0.0.0.0')
        mock_utils.add_static_route.side_effect = [side_effect]
        self._httpservice._check_metadata_ip_route()
        mock_utils.check_os_version.assert_called_once_with(6, 0)
        mock_urlparse.assert_called_with(CONF.metadata_base_url)
        mock_split[0].startswith.assert_called_once_with("169.254.")
        mock_utils.check_static_route_exists.assert_called_once_with(
            mock_split[0])
        mock_utils.get_default_gateway.assert_called_once_with()
        mock_utils.add_static_route.assert_called_once_with(
            mock_split[0], "255.255.255.255", '0.0.0.0', 1, 10)

    def test_test_check_metadata_ip_route(self):
        self._test_check_metadata_ip_route(side_effect=None)

    def test_test_check_metadata_ip_route_fail(self):
        self._test_check_metadata_ip_route(side_effect=Exception)

    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._check_metadata_ip_route')
    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '.get_meta_data')
    def _test_load(self, mock_get_meta_data, mock_check_metadata_ip_route,
                   side_effect):
        mock_get_meta_data.side_effect = [side_effect]
        response = self._httpservice.load()
        mock_check_metadata_ip_route.assert_called_once_with()
        mock_get_meta_data.assert_called_once_with('openstack')
        if side_effect:
            self.assertEqual(response, False)
        else:
            self.assertEqual(response, True)

    def test_load(self):
        self._test_load(side_effect=None)

    def test_load_exception(self):
        self._test_load(side_effect=Exception)

    @mock.patch('urllib2.urlopen')
    def _test_get_response(self, mock_urlopen, side_effect):
        mock_req = mock.MagicMock
        if side_effect and side_effect.code is 404:
            mock_urlopen.side_effect = [side_effect]
            self.assertRaises(base.NotExistingMetadataException,
                              self._httpservice._get_response,
                              mock_req)
        elif side_effect and side_effect.code:
            mock_urlopen.side_effect = [side_effect]
            self.assertRaises(Exception, self._httpservice._get_response,
                              mock_req)
        else:
            mock_urlopen.return_value = 'fake url'
            response = self._httpservice._get_response(mock_req)
            self.assertEqual(response, 'fake url')

    def test_get_response_fail_HTTPError(self):
        error = urllib2.HTTPError("http://169.254.169.254/", 404,
                                  'test error 404', {},  None)
        self._test_get_response(side_effect=error)

    def test_get_response_fail_other_exception(self):
        error = urllib2.HTTPError("http://169.254.169.254/", 409,
                                  'test error 409', {}, None)
        self._test_get_response(side_effect=error)

    def test_get_response(self):
        self._test_get_response(side_effect=None)

    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._get_response')
    @mock.patch('posixpath.join')
    @mock.patch('urllib2.Request')
    def test_get_data(self, mock_Request, mock_posix_join,
                      mock_get_response):
        fake_path = os.path.join('fake', 'path')
        mock_data = mock.MagicMock()
        mock_norm_path = mock.MagicMock()
        mock_req = mock.MagicMock()
        mock_get_response.return_value = mock_data
        mock_posix_join.return_value = mock_norm_path
        mock_Request.return_value = mock_req

        response = self._httpservice._get_data(fake_path)

        mock_posix_join.assert_called_with(CONF.metadata_base_url, fake_path)
        mock_Request.assert_called_once_with(mock_norm_path)
        mock_get_response.assert_called_once_with(mock_req)
        self.assertEqual(response, mock_data.read())

    @mock.patch('cloudbaseinit.metadata.services.httpservice.HttpService'
                '._get_response')
    @mock.patch('posixpath.join')
    @mock.patch('urllib2.Request')
    def test_post_data(self, mock_Request, mock_posix_join,
                       mock_get_response):
        fake_path = os.path.join('fake', 'path')
        fake_data = 'fake data'
        mock_data = mock.MagicMock()
        mock_norm_path = mock.MagicMock()
        mock_req = mock.MagicMock()
        mock_get_response.return_value = mock_data
        mock_posix_join.return_value = mock_norm_path
        mock_Request.return_value = mock_req

        response = self._httpservice._post_data(fake_path, fake_data)

        mock_posix_join.assert_called_with(CONF.metadata_base_url,
                                           fake_path)
        mock_Request.assert_called_once_with(mock_norm_path, data=fake_data)
        mock_get_response.assert_called_once_with(mock_req)
        self.assertEqual(response, True)
