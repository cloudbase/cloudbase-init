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

import importlib
import mock
import unittest

from oslo.config import cfg

CONF = cfg.CONF


class CloudConfigPluginTests(unittest.TestCase):

    def setUp(self):
        self._yaml_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules', {'yaml': self._yaml_mock})
        self._module_patcher.start()
        self.cloudconfig = importlib.import_module(
            'cloudbaseinit.plugins.windows.userdataplugins.cloudconfig')
        self._cloudconfig = self.cloudconfig.CloudConfigPlugin()

    def tearDown(self):
        self._module_patcher.stop()

    def test_decode_steps(self):
        expected_return_value = [
            [self.cloudconfig.GZIP_MIME], [self.cloudconfig.BASE64_MIME],
            [self.cloudconfig.BASE64_MIME, self.cloudconfig.GZIP_MIME],
            [self.cloudconfig.DEFAULT_MIME_TYPE],
            [self.cloudconfig.DEFAULT_MIME_TYPE]
        ]
        return_value = [self.cloudconfig.decode_steps(encoding)
                        for encoding in ('gz', 'b64', 'gz+b64', 'fake', '')]

        self.assertEqual(expected_return_value, return_value)

    def test_process_permissions(self):
        for permissions in (0o644, '0644', '0o644', 420, 420.1):
            self.assertEqual(
                420, self.cloudconfig.process_permissions(permissions))

        response = self.cloudconfig.process_permissions(mock.sentinel.invalid)
        self.assertEqual(self.cloudconfig.DEFAULT_PERMISSIONS, response)

    def test_priority(self):
        in_list = mock.sentinel.in_list
        not_in_list = mock.sentinel.not_in_list
        self._cloudconfig._plugins_order = [in_list]

        self.assertEqual(0, self._cloudconfig._priority(in_list))
        self.assertEqual(1, self._cloudconfig._priority(not_in_list))

    @mock.patch('yaml.load')
    def test_content(self, mock_yaml_load):
        mock_yaml_load.side_effect = [
            ValueError("Invalid yaml stream provided."),
            mock.sentinel.not_dict,
            {}
        ]

        for expected_return_value in (False, False, []):
            return_value = self._cloudconfig._content(mock.sentinel.part)
            self.assertEqual(expected_return_value, return_value)

        self.assertEqual(3, mock_yaml_load.call_count)

    @mock.patch('base64.b64decode')
    @mock.patch('gzip.GzipFile.read')
    @mock.patch('io.BytesIO')
    def test_process_content(self, mock_bytes_io, mock_gzip_file,
                             mock_b64decode):
        content = mock.sentinel.content
        mock_gzip_file.return_value = content
        mock_b64decode.return_value = content

        for encoding in ('gz', 'b64', 'gz+b64'):
            return_value = self.cloudconfig.process_content(content, encoding)
            self.assertEqual(content, return_value)

        self.assertEqual(2, mock_bytes_io.call_count)
        self.assertEqual(2, mock_gzip_file.call_count)
        self.assertEqual(2, mock_b64decode.call_count)

    @mock.patch('base64.b64decode')
    @mock.patch('gzip.GzipFile.read')
    @mock.patch('io.BytesIO')
    def test_process_content_fail(self, mock_bytes_io, mock_gzip_file,
                                  mock_b64decode):
        content = mock.sentinel.content
        mock_gzip_file.side_effect = [IOError(), ValueError()]
        mock_b64decode.side_effect = [ValueError(), TypeError()]

        for encoding in ('gz', 'b64', 'gz+b64'):
            return_value = self.cloudconfig.process_content(content, encoding)
            self.assertEqual(str(content), return_value)

        self.assertEqual(2, mock_bytes_io.call_count)
        self.assertEqual(2, mock_gzip_file.call_count)
        self.assertEqual(2, mock_b64decode.call_count)

    @mock.patch('os.path.dirname')
    @mock.patch('os.path.isdir')
    @mock.patch('os.makedirs')
    @mock.patch('os.chmod')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.process_permissions')
    def test_write_files(self, mock_process_permissions,
                         mock_chmod, mock_makedires, mock_isdir,
                         mock_dirname):

        path = mock.sentinel.path
        permissions = mock.sentinel.permissions
        content = mock.sentinel.content
        open_mode = mock.sentinel.open_mode
        mock_dirname.return_value = mock.sentinel.dirname
        mock_isdir.return_value = False

        with mock.patch('cloudbaseinit.plugins.windows.userdataplugins.'
                        'cloudconfig.open', mock.mock_open(), create=True):
            self.cloudconfig.write_file(path, content, permissions, open_mode)

        mock_dirname.assert_called_once_with(path)
        mock_isdir.assert_called_once_with(mock.sentinel.dirname)
        mock_makedires.assert_called_once_with(mock.sentinel.dirname)
        mock_chmod.assert_called_once_with(path, permissions)

    @mock.patch('os.path.dirname')
    @mock.patch('os.path.isdir')
    @mock.patch('os.makedirs')
    def test_write_files_fail(self, mock_makedires, mock_isdir,
                              mock_dirname):
        path = mock.sentinel.path
        permissions = mock.sentinel.permissions
        content = mock.sentinel.content
        open_mode = mock.sentinel.open_mode

        mock_dirname.return_value = mock.sentinel.dirname
        mock_isdir.return_value = False
        mock_makedires.side_effect = [OSError()]

        return_value = self.cloudconfig.write_file(path, content, permissions,
                                                   open_mode)
        mock_dirname.assert_called_once_with(path)
        mock_isdir.assert_called_once_with(mock.sentinel.dirname)
        mock_makedires.assert_called_once_with(mock.sentinel.dirname)
        self.assertFalse(return_value)

    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.process_content')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.process_permissions')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.write_file')
    @mock.patch('os.path.abspath')
    def test_plugin_write_files(self, mock_abspath, mock_write_file,
                                mock_process_permissions,
                                mock_process_content):
        path = mock.sentinel.path
        content = mock.sentinel.content
        permissions = mock.sentinel.permissions
        files = [{'path': path, 'content': content}]

        mock_abspath.return_value = path
        mock_process_permissions.return_value = permissions
        mock_process_content.return_value = content

        self._cloudconfig.plugin_write_files(files)
        mock_abspath.assert_called_once_with(path)
        mock_process_permissions.assert_called_once_with(None)
        mock_process_content.assert_called_once_with(content, None)
        mock_write_file.assert_called_once_with(path, content, permissions)

    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.process_content')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.process_permissions')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.write_file')
    @mock.patch('os.path.abspath')
    def test_plugin_write_files_fail(self, mock_abspath, mock_write_file,
                                     mock_process_permissions,
                                     mock_process_content):

        self._cloudconfig.plugin_write_files([{}])
        self.assertEqual(0, mock_abspath.call_count)
        self.assertEqual(0, mock_process_permissions.call_count)
        self.assertEqual(0, mock_process_content.call_count)
        self.assertEqual(0, mock_write_file.call_count)

    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.CloudConfigPlugin.plugin_write_files')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.CloudConfigPlugin._content')
    def test_process(self, mock_content, mock_plugin_write_files):
        mock_content.side_effect = [
            [("write_files", mock.sentinel.content)],
            [("invalid_plugin", mock.sentinel.content)]
        ]
        mock_part = mock.sentinel.part

        self._cloudconfig.process(mock_part)
        mock_plugin_write_files.assert_called_once_with(mock.sentinel.content)
        mock_content.assert_called_once_with(mock_part)

        mock_plugin_write_files.reset_mock()
        self._cloudconfig.process(mock_part)
        self.assertEqual(0, mock_plugin_write_files.call_count)

    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.CloudConfigPlugin.plugin_write_files')
    @mock.patch('cloudbaseinit.plugins.windows.userdataplugins.cloudconfig'
                '.CloudConfigPlugin._content')
    def test_process_fail(self, mock_content, mock_plugin_write_files):
        mock_content.return_value = [("write_files", mock.sentinel.content)]
        mock_plugin_write_files.side_effect = [ValueError()]
        mock_part = mock.sentinel.part

        self._cloudconfig.process(mock_part)
        mock_content.assert_called_once_with(mock_part)
        mock_plugin_write_files.assert_called_once_with(mock.sentinel.content)
