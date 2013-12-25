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

from cloudbaseinit.metadata.services import ec2service
from cloudbaseinit.openstack.common import cfg

CONF = cfg.CONF


class Ec2ServiceTest(unittest.TestCase):

    def setUp(self):
        self._ec2service = ec2service.EC2Service()

    @mock.patch('cloudbaseinit.metadata.services.ec2service.EC2Service'
                '.get_meta_data')
    def _test_load(self, mock_get_meta_data, side_effect):
        mock_get_meta_data.side_effect = [side_effect]
        response = self._ec2service.load()
        mock_get_meta_data.assert_called_once_with('openstack')
        if side_effect is Exception:
            self.assertFalse(response)
        else:
            self.assertTrue(response)

    def test_load_exception(self):
        self._test_load(side_effect=Exception)

    def test_load(self):
        self._test_load(side_effect='fake data')

    @mock.patch('posixpath.join')
    @mock.patch('urllib2.Request')
    @mock.patch('urllib2.urlopen')
    @mock.patch('cloudbaseinit.metadata.services.ec2service.EC2Service'
                '._load_public_keys')
    @mock.patch('cloudbaseinit.metadata.services.ec2service.EC2Service'
                '._check_EC2')
    @mock.patch('cloudbaseinit.metadata.services.ec2service.EC2Service'
                '._get_EC2_value')
    def _test_get_data(self, mock_get_EC2_value, mock_check_EC2,
                       mock_load_public_keys,  mock_urlopen,
                       mock_Request, mock_join, check_ec2, data_type):
        mock_path = mock.MagicMock()
        mock_req = mock.MagicMock()
        mock_response = mock.MagicMock()
        fake_path = os.path.join('fake', 'path')
        mock_join.return_value = fake_path
        mock_check_EC2.return_value = check_ec2
        mock_Request.return_value = mock_req
        mock_urlopen.return_value = mock_response
        mock_response.read.return_value = 'fake data'
        mock_path.endswith.return_value = data_type

        if check_ec2 is None:
            self.assertRaises(Exception, self._ec2service._get_data,
                              mock_path)

        elif data_type is 'meta_data.json':
            response = self._ec2service._get_data(mock_path)
            print response
            for key in ec2service.ec2nodes:
                mock_get_EC2_value.assert_called_with(key)
                mock_load_public_keys.assert_called_with()

        elif data_type is 'user_data':
            response = self._ec2service._get_data(mock_path)
            mock_join.assert_called_with(CONF.ec2_metadata_base_url,
                                         'user-data')
            mock_Request.assert_called_once_with(fake_path)
            mock_urlopen.assert_called_once_with(mock_req)
            mock_response.read.assert_called_once_with()
            self.assertEqual(response, 'fake data')

    def test_get_data_metadata_json(self):
        self._test_get_data(check_ec2=True, data_type='meta_data.json')

    def test_get_data_user_data(self):
        self._test_get_data(check_ec2=True, data_type='user_data')

    def test_get_data_no_EC2(self):
        self._test_get_data(check_ec2=None, data_type=None)

    @mock.patch('cloudbaseinit.metadata.services.ec2service.EC2Service'
                '._get_EC2_value')
    def _test_check_EC2(self, mock_get_EC2_value, side_effect):
        mock_get_EC2_value.side_effect = [side_effect]
        response = self._ec2service._check_EC2()
        if side_effect is Exception:
            self.assertFalse(response)
        else:
            self.assertTrue(response)

    def test_check_EC2_Exception(self):
        self._test_check_EC2(side_effect=Exception)

    def test_check_EC2(self):
        self._test_check_EC2(side_effect='fake value')

    @mock.patch('posixpath.join')
    @mock.patch('urllib2.Request')
    @mock.patch('urllib2.urlopen')
    def test_get_EC2_value(self, mock_urlopen, mock_Request, mock_join):
        mock_key = mock.MagicMock()
        mock_response = mock.MagicMock()
        fake_path = os.path.join('fake', 'path')
        mock_join.return_value = fake_path
        mock_Request.return_value = 'fake req'
        mock_urlopen.return_value = mock_response
        mock_response.read.return_value = 'fake data'
        response = self._ec2service._get_EC2_value(mock_key)
        mock_join.assert_called_with(CONF.ec2_metadata_base_url,
                                     'meta-data', mock_key)
        mock_Request.assert_called_once_with(fake_path)
        mock_urlopen.assert_called_once_with('fake req')
        mock_response.read.assert_called_once_with()
        self.assertEqual(response, 'fake data')

    @mock.patch('cloudbaseinit.metadata.services.ec2service.EC2Service'
                '._get_EC2_value')
    def test_load_public_keys(self, mock_get_EC2_value):
        data = {}
        key_list = mock.MagicMock()
        mock_get_EC2_value.return_value = key_list
        self._ec2service._load_public_keys(data)
        mock_get_EC2_value.assert_called_with('public-keys/')
        self.assertEqual(data['public_keys'], {})
