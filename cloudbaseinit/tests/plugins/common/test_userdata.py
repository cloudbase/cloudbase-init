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

import os
import pkgutil
import tempfile
import textwrap
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.metadata.services import base as metadata_services_base
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import userdata
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils


class FakeService(object):
    def __init__(self, user_data):
        self.user_data = user_data

    def get_decoded_user_data(self):
        return self.user_data.encode()


def _create_tempfile():
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    return tmp


class UserDataPluginTest(unittest.TestCase):

    def setUp(self):
        self._userdata = userdata.UserDataPlugin()
        self.fake_data = fake_json_response.get_fake_metadata_json(
            '2013-04-04')

    @mock.patch('cloudbaseinit.plugins.common.userdata.UserDataPlugin'
                '._process_user_data')
    def _test_execute(self, mock_process_user_data, ret_val):
        mock_service = mock.MagicMock()
        mock_service.get_decoded_user_data.side_effect = [ret_val]

        response = self._userdata.execute(service=mock_service,
                                          shared_data=None)

        mock_service.get_decoded_user_data.assert_called_once_with()
        if ret_val is metadata_services_base.NotExistingMetadataException:
            self.assertEqual(response, (base.PLUGIN_EXECUTION_DONE, False))
        elif ret_val is None:
            self.assertEqual(response, (base.PLUGIN_EXECUTION_DONE, False))

    def test_execute(self):
        self._test_execute(ret_val='fake_data')

    def test_execute_no_data(self):
        self._test_execute(ret_val=None)

    def test_execute_NotExistingMetadataException(self):
        self._test_execute(
            ret_val=metadata_services_base.NotExistingMetadataException)

    def test_execute_not_user_data(self):
        self._test_execute(ret_val=None)

    @mock.patch('email.message_from_string')
    @mock.patch('cloudbaseinit.utils.encoding.get_as_string')
    def test_parse_mime(self, mock_get_as_string,
                        mock_message_from_string):
        fake_user_data = textwrap.dedent('''
        -----BEGIN CERTIFICATE-----
        MIIDGTCCAgGgAwIBAgIJAN5fj7R5dNrMMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
        BAMTFmNsb3VkYmFzZS1pbml0LWV4YW1wbGUwHhcNMTUwNDA4MTIyNDI1WhcNMjUw
        ''')
        expected_logging = ['User data content:\n%s' % fake_user_data]
        mock_get_as_string.return_value = fake_user_data

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdata') as snatcher:
            response = self._userdata._parse_mime(user_data=fake_user_data)

        mock_get_as_string.assert_called_once_with(fake_user_data)
        mock_message_from_string.assert_called_once_with(
            mock_get_as_string.return_value)
        self.assertEqual(response, mock_message_from_string().walk())
        self.assertEqual(expected_logging, snatcher.output)

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.factory.'
                'load_plugins')
    @mock.patch('cloudbaseinit.plugins.common.userdata.UserDataPlugin'
                '._parse_mime')
    @mock.patch('cloudbaseinit.plugins.common.userdata.UserDataPlugin'
                '._process_part')
    @mock.patch('cloudbaseinit.plugins.common.userdata.UserDataPlugin'
                '._end_part_process_event')
    @mock.patch('cloudbaseinit.plugins.common.userdata.UserDataPlugin'
                '._process_non_multi_part')
    def _test_process_user_data(self, mock_process_non_multi_part,
                                mock_end_part_process_event,
                                mock_process_part, mock_parse_mime,
                                mock_load_plugins, user_data, reboot):
        mock_part = mock.MagicMock()
        mock_parse_mime.return_value = [mock_part]
        mock_process_part.return_value = (base.PLUGIN_EXECUTION_DONE, reboot)

        response = self._userdata._process_user_data(user_data=user_data)

        if user_data.startswith(b'Content-Type: multipart'):
            mock_load_plugins.assert_called_once_with()
            mock_parse_mime.assert_called_once_with(user_data)
            mock_process_part.assert_called_once_with(mock_part,
                                                      mock_load_plugins(), {})
            self.assertEqual((base.PLUGIN_EXECUTION_DONE, reboot), response)
        else:
            mock_process_non_multi_part.assert_called_once_with(user_data)
            self.assertEqual(mock_process_non_multi_part.return_value,
                             response)

    def test_process_user_data_multipart_reboot_true(self):
        self._test_process_user_data(user_data=b'Content-Type: multipart',
                                     reboot=True)

    def test_process_user_data_multipart_reboot_false(self):
        self._test_process_user_data(user_data=b'Content-Type: multipart',
                                     reboot=False)

    def test_process_user_data_non_multipart(self):
        self._test_process_user_data(user_data=b'Content-Type: non-multipart',
                                     reboot=False)

    @mock.patch('cloudbaseinit.plugins.common.userdata.UserDataPlugin'
                '._add_part_handlers')
    @mock.patch('cloudbaseinit.plugins.common.execcmd'
                '.get_plugin_return_value')
    def _test_process_part(self, mock_get_plugin_return_value,
                           mock_add_part_handlers,
                           handler_func, user_data_plugin, content_type):
        mock_part = mock.MagicMock()
        mock_user_data_plugins = mock.MagicMock()
        mock_user_handlers = mock.MagicMock()
        mock_user_handlers.get.side_effect = [handler_func]
        mock_user_data_plugins.get.side_effect = [user_data_plugin]
        if content_type:
            _content_type = self._userdata._PART_HANDLER_CONTENT_TYPE
            mock_part.get_content_type.return_value = _content_type
        else:
            _content_type = 'other content type'
            mock_part.get_content_type.return_value = _content_type

        response = self._userdata._process_part(
            part=mock_part, user_data_plugins=mock_user_data_plugins,
            user_handlers=mock_user_handlers)
        mock_part.get_content_type.assert_called_once_with()
        mock_user_handlers.get.assert_called_once_with(
            _content_type)
        if handler_func and handler_func is Exception:
            self.assertEqual(2, mock_part.get_content_type.call_count)
            self.assertEqual(2, mock_part.get_filename.call_count)
        elif handler_func:
            handler_func.assert_called_once_with(None, _content_type,
                                                 mock_part.get_filename(),
                                                 mock_part.get_payload())

            self.assertEqual(1, mock_part.get_content_type.call_count)
            self.assertEqual(2, mock_part.get_filename.call_count)
        else:
            mock_user_data_plugins.get.assert_called_once_with(_content_type)
            if user_data_plugin and content_type:
                user_data_plugin.process.assert_called_with(mock_part)
                mock_add_part_handlers.assert_called_with(
                    mock_user_data_plugins, mock_user_handlers,
                    user_data_plugin.process())
            elif user_data_plugin and not content_type:
                mock_get_plugin_return_value.assert_called_once_with(
                    user_data_plugin.process())
                self.assertEqual(mock_get_plugin_return_value.return_value,
                                 response)

    def test_process_part(self):
        handler_func = mock.MagicMock()
        self._test_process_part(handler_func=handler_func,
                                user_data_plugin=None, content_type=False)

    def test_process_part_no_handler_func(self):
        user_data_plugin = mock.MagicMock()
        self._test_process_part(handler_func=None,
                                user_data_plugin=user_data_plugin,
                                content_type=True)

    def test_process_part_not_content_type(self):
        user_data_plugin = mock.MagicMock()
        self._test_process_part(handler_func=None,
                                user_data_plugin=user_data_plugin,
                                content_type=False)

    @mock.patch('cloudbaseinit.plugins.common.userdata.UserDataPlugin'
                '._begin_part_process_event')
    def _test_add_part_handlers(self, mock_begin_part_process_event, ret_val):
        mock_user_data_plugins = mock.MagicMock(spec=dict)
        mock_new_user_handlers = mock.MagicMock(spec=dict)
        mock_user_handlers = mock.MagicMock(spec=dict)
        mock_handler_func = mock.MagicMock()

        mock_new_user_handlers.items.return_value = [('fake content type',
                                                     mock_handler_func)]
        if ret_val:
            mock_user_data_plugins.get.return_value = mock_handler_func
        else:
            mock_user_data_plugins.get.return_value = None

        self._userdata._add_part_handlers(
            user_data_plugins=mock_user_data_plugins,
            user_handlers=mock_user_handlers,
            new_user_handlers=mock_new_user_handlers)
        mock_user_data_plugins.get.assert_called_with('fake content type')
        if ret_val is None:
            mock_user_handlers.__setitem__.assert_called_once_with(
                'fake content type', mock_handler_func)
            mock_begin_part_process_event.assert_called_with(mock_handler_func)

    def test_add_part_handlers(self):
        self._test_add_part_handlers(ret_val=None)

    def test_add_part_handlers_skip_part_handler(self):
        mock_func = mock.MagicMock()
        self._test_add_part_handlers(ret_val=mock_func)

    def test_begin_part_process_event(self):
        mock_handler_func = mock.MagicMock()
        self._userdata._begin_part_process_event(
            handler_func=mock_handler_func)
        mock_handler_func.assert_called_once_with(None, "__begin__", None,
                                                  None)

    def test_end_part_process_event(self):
        mock_handler_func = mock.MagicMock()
        self._userdata._end_part_process_event(
            handler_func=mock_handler_func)
        mock_handler_func.assert_called_once_with(None, "__end__", None,
                                                  None)

    @mock.patch('cloudbaseinit.plugins.common.userdatautils'
                '.execute_user_data_script')
    def test_process_non_multi_part(self, mock_execute_user_data_script):
        user_data = b'fake'
        status, reboot = self._userdata._process_non_multi_part(
            user_data=user_data)
        mock_execute_user_data_script.assert_called_once_with(user_data)
        self.assertEqual(status, 1)
        self.assertFalse(reboot)

    @mock.patch('cloudbaseinit.plugins.common.userdatautils'
                '.execute_user_data_script')
    def test_process_non_multipart_dont_process_x509(
            self, mock_execute_user_data_script):
        user_data = textwrap.dedent('''
        -----BEGIN CERTIFICATE-----
        MIIC9zCCAd8CAgPoMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMUEHVidW50dUBs
        b2NhbGhvc3QwHhcNMTUwNjE1MTAyODUxWhcNMjUwNjEyMTAyODUxWjAbMRkwFwYD
        -----END CERTIFICATE-----
        ''').encode()
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'common.userdata') as snatcher:
            status, reboot = self._userdata._process_non_multi_part(
                user_data=user_data)

        expected_logging = ['Found X509 certificate in userdata']
        self.assertFalse(mock_execute_user_data_script.called)
        self.assertEqual(expected_logging, snatcher.output)
        self.assertEqual(1, status)
        self.assertFalse(reboot)

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.factory.'
                'load_plugins')
    def test_process_non_multi_part_cloud_config(self, mock_load_plugins):
        user_data = b'#cloud-config'
        mock_return_value = mock.sentinel.return_value
        mock_cloud_config_plugin = mock.Mock()
        mock_cloud_config_plugin.process.return_value = mock_return_value
        mock_load_plugins.return_value = {
            'text/cloud-config': mock_cloud_config_plugin}
        status, reboot = self._userdata._process_non_multi_part(
            user_data=user_data)

        mock_load_plugins.assert_called_once_with()
        (mock_cloud_config_plugin
         .process_non_multipart
         .assert_called_once_with(user_data))
        self.assertEqual(status, 1)
        self.assertFalse(reboot)


class TestCloudConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = userdata.UserDataPlugin()
        cls.userdata = pkgutil.get_data('cloudbaseinit.tests.resources',
                                        'cloud_config_userdata').decode()

    def create_tempfiles(self, number):
        for _ in range(number):
            tmp = _create_tempfile()
            self.addCleanup(os.remove, tmp)
            yield tmp

    def test_cloud_config_multipart(self):
        b64, b64_binary, gz, gz_binary = list(self.create_tempfiles(4))

        service = FakeService(self.userdata.format(b64=b64,
                                                   b64_binary=b64_binary,
                                                   gzip=gz,
                                                   gzip_binary=gz_binary))
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'common.userdataplugins.'
                                   'cloudconfigplugins') as snatcher:
            status, reboot = self.plugin.execute(service, {})

        for path in (b64, b64_binary, gz, gz_binary):
            self.assertTrue(os.path.exists(path),
                            "Path {} should exist.".format(path))
            with open(path) as stream:
                self.assertEqual('42', stream.read())

        self.assertEqual(status, 1)
        self.assertFalse(reboot)
        expected_logging = [
            'Unknown encoding, doing nothing.',
            'Fail to process permissions None, assuming 420',
            'Fail to process permissions None, assuming 420',
            'Fail to process permissions None, assuming 420'
        ]
        self.assertEqual(expected_logging, snatcher.output)
