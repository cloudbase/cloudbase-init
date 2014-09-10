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
import posixpath
import unittest

from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.utils import x509constants
from oslo.config import cfg

CONF = cfg.CONF


class BaseOpenStackServiceTest(unittest.TestCase):
    def setUp(self):
        CONF.set_override('retry_count_interval', 0)
        self._service = baseopenstackservice.BaseOpenStackService()

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_cache_data")
    def test_get_content(self, mock_get_cache_data):
        response = self._service.get_content('fake name')
        path = posixpath.join('openstack', 'content', 'fake name')
        mock_get_cache_data.assert_called_once_with(path)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._service.get_user_data()
        path = posixpath.join('openstack', 'latest', 'user_data')
        mock_get_cache_data.assert_called_once_with(path)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_cache_data")
    def test_get_meta_data(self, mock_get_cache_data):
        mock_get_cache_data.return_value = b'{"fake": "data"}'
        response = self._service._get_meta_data(
            version='fake version')
        path = posixpath.join('openstack', 'fake version', 'meta_data.json')
        mock_get_cache_data.assert_called_with(path)
        self.assertEqual({"fake": "data"}, response)

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_meta_data")
    def test_get_instance_id(self, mock_get_meta_data):
        response = self._service.get_instance_id()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('uuid')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_meta_data")
    def test_get_host_name(self, mock_get_meta_data):
        response = self._service.get_host_name()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('hostname')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_meta_data")
    def test_get_public_keys(self, mock_get_meta_data):
        response = self._service.get_public_keys()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('public_keys')
        self.assertEqual(mock_get_meta_data().get().values(), response)

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_meta_data")
    def test_get_network_config(self, mock_get_meta_data):
        response = self._service.get_network_config()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('network_config')
        self.assertEqual(response, mock_get_meta_data().get())

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_meta_data")
    def _test_get_admin_password(self, mock_get_meta_data, meta_data):
        mock_get_meta_data.return_value = meta_data
        response = self._service.get_admin_password()
        mock_get_meta_data.assert_called_once_with()
        if meta_data and 'admin_pass' in meta_data:
            self.assertEqual(meta_data['admin_pass'], response)
        elif meta_data and 'admin_pass' in meta_data.get('meta'):
            self.assertEqual(meta_data.get('meta')['admin_pass'], response)
        else:
            self.assertEqual(None, response)

    def test_get_admin_pass(self):
        self._test_get_admin_password(meta_data={'admin_pass': 'fake pass'})

    def test_get_admin_pass_in_meta(self):
        self._test_get_admin_password(
            meta_data={'meta': {'admin_pass': 'fake pass'}})

    def test_get_admin_pass_no_pass(self):
        self._test_get_admin_password(meta_data={})

    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService._get_meta_data")
    @mock.patch("cloudbaseinit.metadata.services.baseopenstackservice"
                ".BaseOpenStackService.get_user_data")
    def _test_get_client_auth_certs(self, mock_get_user_data,
                                    mock_get_meta_data, meta_data,
                                    ret_value=None):
        mock_get_meta_data.return_value = meta_data
        mock_get_user_data.side_effect = [ret_value]
        response = self._service.get_client_auth_certs()
        mock_get_meta_data.assert_called_once_with()
        if 'meta' in meta_data:
            self.assertEqual(['fake cert'], response)
        elif type(ret_value) is str and ret_value.startswith(
                x509constants.PEM_HEADER):
            mock_get_user_data.assert_called_once_with()
            self.assertEqual([ret_value], response)
        elif ret_value is base.NotExistingMetadataException:
            self.assertEqual(None, response)

    def test_get_client_auth_certs(self):
        self._test_get_client_auth_certs(
            meta_data={'meta': {'admin_cert0': 'fake cert'}})

    def test_get_client_auth_certs_no_cert_data(self):
        self._test_get_client_auth_certs(
            meta_data={}, ret_value=x509constants.PEM_HEADER)

    def test_get_client_auth_certs_no_cert_data_exception(self):
        self._test_get_client_auth_certs(
            meta_data={}, ret_value=base.NotExistingMetadataException)
