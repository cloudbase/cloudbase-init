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
import tempfile
import uuid
import unittest

from cloudbaseinit.metadata.services import base as base_metadata
from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.plugins.windows import userdata
from cloudbaseinit.tests.metadata import fake_json_response

CONF = cfg.CONF


class UserDataPluginTest(unittest.TestCase):

    def setUp(self):
        self._userdata = userdata.UserDataPlugin()
        self.fake_data = fake_json_response.get_fake_metadata_json(
            '2013-04-04')

    @mock.patch('os.path')
    def test_get_plugin_path(self, mock_ospath):
        mock_ospath.join.return_value = 'fake path'
        response = self._userdata._get_plugin_path()
        mock_ospath.join.assert_called_with(
            mock_ospath.dirname(mock_ospath.dirname(mock_ospath.realpath())),
            "windows/userdata-plugins")
        self.assertEqual(response, 'fake path')

    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._process_userdata')
    def _test_execute(self, mock_process_userdata, user_data, exception):
        mock_service = mock.MagicMock()
        fake_shared_data = 'fake data'
        if exception:
            e = base_metadata.NotExistingMetadataException()
            mock_service.side_effect = e
        else:
            mock_service.get_user_data.return_value = user_data
        response = self._userdata.execute(mock_service, fake_shared_data)
        mock_service.get_user_data.assert_called_with('openstack')
        if user_data:
            mock_process_userdata.assert_called_with(user_data)
        self.assertEqual(response, (1, False))

    def test_execute(self):
        self._test_execute(user_data=self.fake_data, exception=False)

    def test_execute_no_data(self):
        self._test_execute(user_data=None, exception=False)

    def test_execute_exception(self):
        self._test_execute(user_data=None, exception=True)

    @mock.patch('cloudbaseinit.plugins.windows.userdata.handle')
    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._parse_mime')
    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._process_part')
    def _test_process_userdata(self, mock_process_part, mock_parse_mime,
                               mock_handle, user_data):
        mock_process_part().__iter__.side_effect = ['fake']
        self._userdata._process_userdata(user_data)
        print mock_parse_mime.mock_calls
        print mock_process_part.mock_calls
        if user_data.startswith('Content-Type: multipart'):
            mock_parse_mime.assert_called_once_with(user_data)
            self.assertEqual(mock_process_part.call_count, 1)
        else:
            mock_handle.assert_called_once_with(user_data)

    def test_process_userdata_multipart(self):
        user_data = 'Content-Type: multipart fake data'
        self._test_process_userdata(user_data=user_data)

    def test_process_userdata(self):
        user_data = 'fake data'
        self._test_process_userdata(user_data=user_data)

    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._get_part_handler')
    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._begin_part_process_event')
    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._end_part_process_event')
    def test_process_part(self, mock_end_part_process_event,
                          mock_begin_part_process_event,
                          mock_get_part_handler):
        mock_part = mock.MagicMock()
        mock_part_handler = mock.MagicMock()
        mock_get_part_handler.return_value = mock_part_handler

        self._userdata._process_part(mock_part)

        mock_get_part_handler.assert_called_once_with(mock_part)
        mock_begin_part_process_event.assert_called_once_with(mock_part)
        mock_part.get_content_type.assert_called_once_with()
        mock_part.get_filename.assert_called_once_with()
        mock_part_handler.process.assert_called_with(mock_part)
        mock_end_part_process_event.assert_called_with(mock_part)

    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._get_custom_handler')
    def test_begin_part_process_event(self, mock_get_custom_handler):
        mock_part = mock.MagicMock()
        mock_handler = mock.MagicMock()
        mock_get_custom_handler.return_value = mock_handler
        self._userdata._begin_part_process_event(mock_part)
        mock_part.get_filename.assert_called_with()
        mock_part.get_payload.assert_called_with()
        mock_handler.assert_called_with("", "__begin__",
                                        mock_part.get_filename(),
                                        mock_part.get_payload())

    @mock.patch('cloudbaseinit.plugins.windows.userdata.UserDataPlugin'
                '._get_custom_handler')
    def test_end_part_process_event(self, mock_get_custom_handler):
        mock_part = mock.MagicMock()
        mock_handler = mock.MagicMock()
        mock_get_custom_handler.return_value = mock_handler
        self._userdata._end_part_process_event(mock_part)
        mock_part.get_payload.assert_called_with()
        mock_handler.assert_called_with("", "__end__",
                                        mock_part.get_filename(),
                                        mock_part.get_payload())

    def test_get_custom_handler(self):
        mock_part = mock.MagicMock()
        mock_part.get_content_type.return_value = 0
        self._userdata.plugin_set.has_custom_handlers = True
        self._userdata.plugin_set.custom_handlers = [0]
        response = self._userdata._get_custom_handler(mock_part)
        mock_part.get_content_type.assert_called_with()
        self.assertEqual(response, 0)

    def test_get_part_handler(self):
        mock_part = mock.MagicMock()
        mock_part.get_content_type.return_value = 0
        self._userdata.plugin_set.set = {0: 'fake value'}
        response = self._userdata._get_part_handler(mock_part)
        mock_part.get_content_type.assert_called_with()
        self.assertEqual(response, 'fake value')

    @mock.patch('email.message_from_string')
    def test_parse_mime(self, mock_message_from_string):
        mock_msg = mock.MagicMock()
        mock_message_from_string.return_value = mock_msg
        response = self._userdata._parse_mime(self.fake_data)
        mock_message_from_string.assert_called_once_with(self.fake_data)
        mock_msg.walk.assert_called_once_with()
        self.assertEqual(response, mock_msg.walk())

    @mock.patch('re.search')
    @mock.patch('tempfile.gettempdir')
    @mock.patch('os.remove')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.join')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.expandvars')
    @mock.patch('cloudbaseinit.osutils.factory.OSUtilsFactory.get_os_utils')
    def _test_handle(self, mock_get_os_utils, mock_path_expandvars,
                     mock_path_exists, mock_path_join, mock_path_isdir,
                     mock_os_remove, mock_gettempdir, mock_re_search,
                     fake_user_data, directory_exists):
        #TODO: recheck, these are old!
        mock_osutils = mock.MagicMock()
        uuid.uuid4 = mock.MagicMock(return_value='randomID')
        mock_path_join.return_value = 'fake_temp\\randomID'
        match_instance = mock.MagicMock()
        path = 'fake_temp\\randomID'
        args = None
        mock_get_os_utils.return_value = mock_osutils

        if fake_user_data == '^rem cmd\s':
            side_effect = [match_instance]
            number_of_calls = 1
            extension = '.cmd'
            args = [path+extension]
            shell = True
        elif fake_user_data == '#!':
            side_effect = [None, match_instance]
            number_of_calls = 2
            extension = '.sh'
            args = ['bash.exe', path+extension]
            shell = False
        elif fake_user_data == '#ps1\s':
            side_effect = [None, None, match_instance]
            number_of_calls = 3
            extension = '.ps1'
            args = ['powershell.exe', '-ExecutionPolicy', 'RemoteSigned',
                    '-NonInteractive', path+extension]
            shell = False
        else:
            side_effect = [None, None, None, match_instance]
            number_of_calls = 4
            extension = '.ps1'
            shell = False
            if directory_exists:
                args = [mock_path_expandvars('%windir%\\sysnative\\'
                                             'WindowsPowerShell\\v1.0\\'
                                             'powershell.exe'),
                        '-ExecutionPolicy',
                        'RemoteSigned', '-NonInteractive', path+extension]
                mock_path_isdir.return_value = True
            else:
                mock_path_isdir.return_value = False

        mock_re_search.side_effect = side_effect

        with mock.patch('cloudbaseinit.plugins.windows.userdata.open',
                        mock.mock_open(), create=True):
            response = userdata.handle(fake_user_data)

        tempfile.gettempdir.assert_called_once_with()

        mock_path_join.assert_called_once_with(mock_gettempdir(),
                                               str(uuid.uuid4()))
        assert mock_re_search.call_count == number_of_calls
        if args:
            mock_osutils.execute_process.assert_called_with(args, shell)

        self.assertEqual(response, (1, False))

    def test_handle_batch(self):
        fake_user_data = '^rem cmd\s'
        self._test_handle(fake_user_data=fake_user_data,
                          directory_exists=True)

    def test_handle_shell(self):
        fake_user_data = '^#!'
        self._test_handle(fake_user_data=fake_user_data,
                          directory_exists=True)

    def test_handle_powershell(self):
        fake_user_data = '^#ps1\s'
        self._test_handle(fake_user_data=fake_user_data,
                          directory_exists=True)

    def test_handle_powershell_sysnative(self):
        fake_user_data = '#ps1_sysnative\s'
        self._test_handle(fake_user_data=fake_user_data,
                          directory_exists=True)

    def test_handle_powershell_sysnative_no_sysnative(self):
        fake_user_data = '#ps1_sysnative\s'
        self._test_handle(fake_user_data=fake_user_data,
                          directory_exists=False)
