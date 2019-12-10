# Copyright 2015 Cloudbase Solutions Srl
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
import sys
import tempfile
import textwrap
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.plugins.common.userdataplugins import cloudconfig
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    write_files
)
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


def _create_tempfile():
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    return tmp


class WriteFilesPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = cloudconfig.CloudConfigPlugin()

    def _get_tempfile(self):
        """Get a temporary file, usable by write_files plugin."""
        tmp = _create_tempfile()
        self.addCleanup(os.remove, tmp)
        # In order to remove the file, we'll need to reset
        # the permissions set by write_file.
        self.addCleanup(os.chmod, tmp, 0o666)
        return tmp

    def test_decode_steps(self):
        pairs = [
            ('gz', [write_files.GZIP_MIME]),
            ('gzip', [write_files.GZIP_MIME]),
            ('b64', [write_files.BASE64_MIME]),
            ('base64', [write_files.BASE64_MIME]),
            ('gz+b64', [write_files.BASE64_MIME, write_files.GZIP_MIME]),
            ('gzip+b64', [write_files.BASE64_MIME, write_files.GZIP_MIME]),
            ('gz+base64', [write_files.BASE64_MIME, write_files.GZIP_MIME]),
            ('gzip+base64', [write_files.BASE64_MIME, write_files.GZIP_MIME]),
            ('fake', []),
            ('', []),
        ]
        for param, expected in pairs:
            self.assertEqual(expected, write_files._decode_steps(param))

    def test_process_permissions(self):
        for permissions in (0o644, '0644', '0o644', 420, 420.1):
            self.assertEqual(
                420, write_files._convert_permissions(permissions))

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            response = write_files._convert_permissions(mock.sentinel.invalid)

        expected_logging = [
            'Fail to process permissions %s, assuming 420'
            % mock.sentinel.invalid
        ]
        self.assertEqual(expected_logging, snatcher.output)
        self.assertEqual(write_files.DEFAULT_PERMISSIONS, response)

    @mock.patch('os.makedirs')
    def test_write_file(self, mk):
        path = u'fake_path'
        content = u'fake_content'
        result = write_files._write_file(path, content, open_mode="w")
        os.remove(path)
        self.assertTrue(result)

    @mock.patch('os.makedirs')
    def test_write_file_excp(self, mock_makedirs):
        mock_makedirs.side_effect = OSError
        result = write_files._write_file(u'fake_path', u'fake_content')
        self.assertFalse(result)

    def test_write_file_list(self):
        expected_logging = [
            "Plugin 'invalid' is currently not supported",
        ]
        code = textwrap.dedent("""
        write_files:
        -   encoding: b64
            content: NDI=
            path: {}
            permissions: '0o466'
        invalid:
        - stuff: 1
        """)
        self._test_write_file(code, expected_logging)

    def test_write_file_dict(self):
        code = textwrap.dedent("""
        write_files:
           encoding: b64
           content: NDI=
           path: {}
           permissions: '0o466'
        """)
        self._test_write_file(code)

    def _test_write_file(self, code, expected_logging=None):
        tmp = self._get_tempfile()
        code = code.format(tmp)

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfig') as snatcher:
            self.plugin.process_non_multipart(code)

        self.assertTrue(os.path.exists(tmp),
                        "Expected path does not exist.")

        with open(tmp) as stream:
            self.assertEqual('42', stream.read())
        if expected_logging is not None:
            self.assertEqual(expected_logging, snatcher.output)

        # Test that the proper permissions were set. On Windows,
        # only the read bit is processed, the rest are ignored.
        permission = oct(os.stat(tmp).st_mode & 0o777)
        if sys.platform == 'win32':
            self.assertEqual(0o444, int(permission, 8))
        else:
            self.assertEqual(0o466, int(permission, 8))

    def test_missing_required_keys(self):
        code = textwrap.dedent("""
        write_files:
        -   c0ntent: NDI=
        """)
        expected_return = [
            "Missing required keys from file "
            "information {'c0ntent': 'NDI='}"
        ]

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            self.plugin.process_non_multipart(code)

        self.assertEqual(expected_return, snatcher.output)

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.'
                'cloudconfigplugins.write_files.WriteFilesPlugin.process')
    def test_processing_plugin_failed(self, mock_write_files):
        mock_write_files.side_effect = ValueError
        code = textwrap.dedent("""
        write_files:
        -   content: NDI=
            path: random_cloudbaseinit_test
        """)

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfig') as snatcher:
            self.plugin.process_non_multipart(code)

        self.assertTrue(snatcher.output[0].startswith(
            "Processing plugin write_files failed"))
        self.assertTrue(snatcher.output[0].endswith("ValueError"))
        self.assertFalse(os.path.exists('random_cloudbaseinit_test'))

    def test_wrong_gzip_content(self):
        tmp = self._get_tempfile()
        code = textwrap.dedent("""
        write_files:
        -   content: lala
            encoding: gz
            path: {}
        """.format(tmp))
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            self.plugin.process_non_multipart(code)

        self.assertTrue(snatcher.output[0].startswith(
            "Fail to decompress gzip content"))

    def test_wrong_b64_content(self):
        tmp = self._get_tempfile()
        code = textwrap.dedent("""
        write_files:
        -   content: l
            encoding: b64
            path: {}
        """.format(tmp))
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            self.plugin.process_non_multipart(code)

        self.assertTrue(snatcher.output[0].startswith(
            "Fail to decode base64 content."))

    def test_unknown_encoding(self):
        tmp = self._get_tempfile()
        code = textwrap.dedent("""
        write_files:
        -   content: NDI=
            path: {}
            encoding: unknown_encoding
            permissions: '0o466'
        """.format(tmp))
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            self.plugin.process_non_multipart(code)

        self.assertTrue(os.path.exists(tmp),
                        "Expected path does not exist.")
        with open(tmp) as stream:
            self.assertEqual('NDI=', stream.read())

        self.assertEqual(["Unknown encoding, assuming plain text."],
                         snatcher.output)

    def test_missing_encoding(self):
        tmp = self._get_tempfile()
        code = textwrap.dedent("""
        write_files:
        -   content: NDI=
            path: {}
            permissions: '0o466'
        """.format(tmp))
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            self.plugin.process_non_multipart(code)

        self.assertTrue(os.path.exists(tmp),
                        "Expected path does not exist.")
        with open(tmp) as stream:
            self.assertEqual('NDI=', stream.read())

        self.assertEqual([], snatcher.output)

    def test_invalid_object_passed(self):
        with self.assertRaises(exception.CloudbaseInitException) as cm:
            write_files.WriteFilesPlugin().process(1)

        expected = "Can't process the type of data %r" % type(1)
        self.assertEqual(expected, str(cm.exception))

    def test_process_item_fail(self):
        fake_data = {}

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            write_files.WriteFilesPlugin()._process_item(fake_data)

        self.assertEqual(['Missing required keys from file information {}'],
                         snatcher.output)

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.'
                'cloudconfigplugins.write_files._process_content')
    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.'
                'cloudconfigplugins.write_files._write_file')
    @mock.patch('os.path.abspath')
    def _test_process_item(self, fake_data,
                           mock_os_path,
                           mock_write_file,
                           mock_process_content):
        fake_path = mock.MagicMock()
        mock_os_path.return_value = fake_path

        fake_content = mock.MagicMock()
        mock_process_content.return_value = fake_content

        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'write_files') as snatcher:
            write_files.WriteFilesPlugin()._process_item(fake_data)

        self.assertEqual(['Fail to process permissions None, assuming 420'],
                         snatcher.output)

        open_mode = 'wb'
        if fake_data.get('append', False) is True:
            open_mode = 'ab'

        mock_write_file.assert_called_with(fake_path, fake_content, 420,
                                           open_mode)

    def test_process_item_write(self):
        self._test_process_item(
            {'path': 'fake_path', 'content': 'fake_content', 'append': False})

    def test_process_item_append(self):
        self._test_process_item(
            {'path': 'fake_path', 'content': 'fake_content', 'append': True})
