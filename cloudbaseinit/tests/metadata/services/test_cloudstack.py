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

import functools
import socket
import unittest
import unittest.mock as mock
import urllib

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import cloudstack
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class CloudStackTest(unittest.TestCase):

    def setUp(self):
        CONF.set_override('retry_count_interval', 0)
        CONF.set_override('retry_count', 1)
        CONF.set_override('add_metadata_private_ip_route', True, 'cloudstack')
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
        self._service._osutils.get_dhcp_hosts_in_use = mock.Mock()
        self._service._osutils.get_dhcp_hosts_in_use.side_effect = [
            [('eth0', mock.sentinel.mac_address, '10.10.0.1'),
             ('eth1', mock.sentinel.mac_address, '10.10.0.2'),
             ('eth2', mock.sentinel.mac_address, '10.10.0.3')]
        ]
        mock_test_api.side_effect = [False, False, False, True]

        self.assertTrue(self._service.load())
        self.assertEqual(4, mock_test_api.call_count)

    @mock.patch('cloudbaseinit.utils.network.check_metadata_ip_route')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._test_api')
    def test_load_default(self, mock_test_api, mock_check_metadata_ip_route):
        mock_test_api.side_effect = [True]
        self._service._test_api = mock_test_api

        self.assertTrue(self._service.load())
        mock_test_api.assert_called_once_with(
            CONF.cloudstack.metadata_base_url)
        mock_check_metadata_ip_route.assert_called_once_with(
            CONF.cloudstack.metadata_base_url)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._test_api')
    def test_load_fail(self, mock_test_api, mock_os_util):
        self._service._osutils.get_dhcp_hosts_in_use.side_effect = [None]
        mock_test_api.side_effect = [False]

        self.assertFalse(self._service.load())  # No DHCP server was found.
        mock_test_api.assert_called_once_with(
            CONF.cloudstack.metadata_base_url)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._test_api')
    def test_load_no_service(self, mock_test_api, mock_os_util):
        self._service._osutils.get_dhcp_hosts_in_use = mock.Mock()
        self._service._osutils.get_dhcp_hosts_in_use.side_effect = [
            [('eth0', mock.sentinel.mac_address,
              CONF.cloudstack.metadata_base_url)]
        ]
        mock_test_api.side_effect = [False, False]

        # No service
        self.assertFalse(self._service.load())
        self.assertEqual(2, mock_test_api.call_count)

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
    def _test_cache_response(self, mock_get_cache_data, method, metadata,
                             decode=True):
        mock_get_cache_data.side_effect = [mock.sentinel.response]
        response = method()

        self.assertEqual(mock.sentinel.response, response)
        cache_assert = functools.partial(
            mock_get_cache_data.assert_called_once_with,
            metadata)
        if decode:
            cache_assert(decode=decode)

    def test_get_instance_id(self):
        self._test_cache_response(method=self._service.get_instance_id,
                                  metadata='latest/meta-data/instance-id')

    def test_get_host_name(self):
        self._test_cache_response(method=self._service.get_host_name,
                                  metadata='latest/meta-data/local-hostname')

    def test_get_user_data(self):
        self._test_cache_response(method=self._service.get_user_data,
                                  metadata='latest/user-data', decode=False)

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

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._password_client')
    def test_get_password(self, mock_password_client):
        headers = {"DomU_Request": "send_my_password"}
        expected_password = "password"
        mock_password_client.return_value = expected_password
        expected_output = [
            "Try to get password from the Password Server.",
            "The password server returned a valid password "
            "for the current instance."
        ]

        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'cloudstack') as snatcher:
            password = self._service._get_password()

        mock_password_client.assert_called_once_with(headers=headers)
        self.assertEqual(expected_password, password)
        self.assertEqual(expected_output, snatcher.output)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._password_client')
    def test_get_password_fail(self, mock_password_client):
        mock_password_client.side_effect = ["",
                                            cloudstack.BAD_REQUEST,
                                            cloudstack.SAVED_PASSWORD]
        expected_output = [
            ["Try to get password from the Password Server.",
             "The password was already taken from the Password Server "
             "for the current instance."],

            ["Try to get password from the Password Server.",
             "The Password Server did not recognize the request."],

            ["Try to get password from the Password Server.",
             "The Password Server did not have any password for the "
             "current instance."],
        ]
        for _ in range(3):
            with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                       'cloudstack') as snatcher:
                self.assertIsNone(self._service._get_password())
                self.assertEqual(expected_output.pop(), snatcher.output)

        self.assertEqual(3, mock_password_client.call_count)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._password_client')
    def test_get_password_exception(self, mock_password_client):
        fake_http_error = urllib.error.HTTPError(url='127.0.0.1', code=404,
                                                 hdrs={}, fp=None,
                                                 msg='error')
        fake_error = OSError(10061, "Connection error")
        mock_password_client.side_effect = [fake_http_error, fake_error]
        expected_output = [
            ["Try to get password from the Password Server.",
             "Getting password failed due to a connection failure."],

            ["Try to get password from the Password Server.",
             "Getting password failed: 404"],
        ]

        for _ in range(2):
            with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                       'cloudstack') as snatcher:
                self.assertIsNone(self._service._get_password())
                self.assertEqual(expected_output.pop(), snatcher.output)

        self.assertEqual(2, mock_password_client.call_count)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack'
                '._password_client')
    def test_delete_password(self, mock_password_client):
        fake_url_error = urllib.error.HTTPError(url='127.0.0.1', code=404,
                                                hdrs={}, fp=None,
                                                msg='error')
        fake_connection_error = OSError(10061, "Connection error")
        mock_password_client.side_effect = [cloudstack.SAVED_PASSWORD,
                                            cloudstack.BAD_REQUEST,
                                            fake_url_error,
                                            fake_connection_error]
        expected_output = [

            ['Remove the password for this instance from the '
             'Password Server.',
             'Removing password failed due to a connection failure.',
             'Failed to remove the password from the Password Server.'],
            ['Remove the password for this instance from the '
             'Password Server.',
             'Removing password failed: 404',
             'Failed to remove the password from the Password Server.'],
            ['Remove the password for this instance from the '
             'Password Server.',
             'Failed to remove the password from the Password Server.'],
            ['Remove the password for this instance from the '
             'Password Server.',
             'The password was removed from the Password Server.'],

        ]

        expected_output_len = len(expected_output)
        for _ in range(expected_output_len):
            with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                       'cloudstack') as snatcher:
                self.assertIsNone(self._service._delete_password())
                self.assertEqual(expected_output.pop(), snatcher.output)

        self.assertEqual(expected_output_len, mock_password_client.call_count)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack.'
                '_delete_password')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack.'
                '_get_password')
    def test_get_admin_password(self, mock_get_password, mock_delete_password):
        mock_get_password.return_value = mock.sentinel.password
        password = self._service.get_admin_password()

        self.assertEqual(mock.sentinel.password, password)
        self.assertEqual(1, mock_get_password.call_count)
        self.assertFalse(mock_delete_password.called)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack.'
                '_delete_password')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack.'
                '_get_password')
    def test_get_admin_password_fail(self, mock_get_password,
                                     mock_delete_password):
        mock_get_password.return_value = None

        self.assertIsNone(self._service.get_admin_password())
        self.assertEqual(1, mock_get_password.call_count)
        self.assertFalse(mock_delete_password.called)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack.'
                '_delete_password')
    def test_confirm_admin_password(self, mock_delete_password):
        self._service.confirm_admin_password(mock.sentinel.password)
        mock_delete_password.assert_called_once_with()

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack.'
                '_delete_password')
    def test_confirm_admin_password_none(self, mock_delete_password):
        self._service.confirm_admin_password(None)
        self.assertFalse(mock_delete_password.called)

    def test_can_update_password(self):
        self.assertTrue(self._service.can_update_password)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.CloudStack.'
                '_get_password')
    def test_is_password_changed(self, mock_get_password):
        mock_get_password.return_value = True
        self.assertTrue(self._service.is_password_changed())


class CloudStackConfigDriveTest(unittest.TestCase):

    def setUp(self):
        self._service = cloudstack.ConfigDrive()

    def test_init_uses_cloudstack_marker(self):
        self.assertEqual('config-2', self._service._drive_label)
        self.assertEqual('cloudstack\\metadata\\instance-id.txt',
                         self._service._metadata_file)

    def test_preprocess_options(self):
        self._service._preprocess_options()
        self.assertEqual(set(['iso']), self._service._searched_types)
        self.assertEqual(set(['cdrom']), self._service._searched_locations)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_cache_data')
    def test_get_instance_id(self, mock_get_cache_data):
        mock_get_cache_data.return_value = 'i-123\r\n'

        self.assertEqual('i-123', self._service.get_instance_id())
        mock_get_cache_data.assert_called_once_with(
            'cloudstack/metadata/instance-id.txt', decode=True)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_cache_data')
    def test_get_password(self, mock_get_cache_data):
        mock_get_cache_data.return_value = 's3cret\r\n'

        self.assertEqual('s3cret', self._service._get_password())
        mock_get_cache_data.assert_called_once_with(
            'cloudstack/password/vm_password.txt', decode=True)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_cache_data')
    def test_get_password_sentinels(self, mock_get_cache_data):
        for value in ('', '  ', cloudstack.SAVED_PASSWORD,
                      cloudstack.SAVED_PASSWORD + '\r\n'):
            mock_get_cache_data.return_value = value
            self.assertIsNone(self._service._get_password())

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_cache_data')
    def test_get_password_missing(self, mock_get_cache_data):
        mock_get_cache_data.side_effect = base.NotExistingMetadataException()
        self.assertIsNone(self._service._get_password())

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_persist_password_hash')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_password')
    def test_get_admin_password(self, mock_get_password, mock_persist):
        mock_get_password.return_value = 's3cret'

        self.assertEqual('s3cret', self._service.get_admin_password())
        self.assertFalse(mock_persist.called)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_persist_password_hash')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_password')
    def test_get_admin_password_none(self, mock_get_password, mock_persist):
        mock_get_password.return_value = None

        self.assertIsNone(self._service.get_admin_password())
        self.assertFalse(mock_persist.called)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_persist_password_hash')
    def test_confirm_admin_password(self, mock_persist):
        self._service.confirm_admin_password('s3cret')
        mock_persist.assert_called_once_with('s3cret')

    def test_can_update_password(self):
        self.assertTrue(self._service.can_update_password)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                'get_instance_id')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_password')
    def test_is_password_changed(self, mock_get_password, mock_instance_id,
                                 mock_get_os_utils):
        mock_get_password.return_value = 's3cret'
        mock_instance_id.return_value = 'i-1'
        mock_osutils = mock_get_os_utils.return_value
        mock_osutils.get_config_value.return_value = None

        self.assertTrue(self._service.is_password_changed())
        mock_osutils.get_config_value.assert_called_once_with(
            'PasswordHash', 'i-1')
        self.assertFalse(mock_osutils.set_config_value.called)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                'get_instance_id')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_password')
    def test_is_password_changed_same_hash(self, mock_get_password,
                                           mock_instance_id,
                                           mock_get_os_utils):
        password = 's3cret'
        mock_get_password.return_value = password
        mock_instance_id.return_value = 'i-1'
        mock_osutils = mock_get_os_utils.return_value
        mock_osutils.get_config_value.return_value = (
            self._service._password_hash(password))

        self.assertFalse(self._service.is_password_changed())
        self.assertFalse(mock_osutils.set_config_value.called)

    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                '_get_password')
    def test_is_password_changed_no_password(self, mock_get_password):
        mock_get_password.return_value = None
        self.assertFalse(self._service.is_password_changed())

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.services.cloudstack.ConfigDrive.'
                'get_instance_id')
    def test_persist_password_hash(self, mock_instance_id, mock_get_os_utils):
        mock_instance_id.return_value = 'i-1'
        mock_osutils = mock_get_os_utils.return_value

        self._service._persist_password_hash('s3cret')
        mock_osutils.set_config_value.assert_called_once_with(
            'PasswordHash', self._service._password_hash('s3cret'), 'i-1')
