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

import importlib
import unittest

import mock
import six

from cloudbaseinit.tests import testutils


class TestVersion(unittest.TestCase):

    def setUp(self):
        self.version = importlib.import_module('cloudbaseinit.version')

    @mock.patch('pbr.version.VersionInfo')
    def test_get_version(self, mock_version_info):
        package_version = self.version.get_version()

        mock_version_info.assert_called_once_with('cloudbase-init')
        release_string = mock_version_info.return_value.release_string
        self.assertEqual(release_string.return_value, package_version)

    @mock.patch('pbr.version.VersionInfo')
    def test_get_canonical_version(self, mock_version_info):
        package_version = self.version.get_canonical_version()

        mock_version_info.assert_called_once_with('cloudbase-init')
        canon_string = (
            mock_version_info.return_value.canonical_version_string)
        self.assertEqual(canon_string.return_value, package_version)

    @mock.patch('requests.get')
    @mock.patch('json.loads')
    def test__read_url(self, mock_loads, mock_get):
        mock_url = mock.Mock()

        result = self.version._read_url(mock_url)

        headers = {'User-Agent': self.version._PRODUCT_NAME}
        mock_get.assert_called_once_with(mock_url, verify=six.PY3,
                                         headers=headers)
        request = mock_get.return_value
        request.raise_for_status.assert_called_once_with()
        mock_loads.assert_called_once_with(request.text)
        self.assertEqual(mock_loads.return_value, result)

    @mock.patch('requests.get')
    def test__read_url_empty_text(self, mock_get):
        mock_get.return_value.text = None

        result = self.version._read_url(mock.Mock())

        self.assertIsNone(result)

    @mock.patch('threading.Thread')
    def test_check_latest_version(self, mock_thread):
        mock_callback = mock.Mock()

        self.version.check_latest_version(mock_callback)

        mock_thread.assert_called_once_with(
            target=self.version._check_latest_version,
            args=(mock_callback, ))
        thread = mock_thread.return_value
        thread.start.assert_called_once_with()

    @mock.patch('cloudbaseinit.version.get_version')
    @mock.patch('cloudbaseinit.version._read_url')
    def test__check_latest_version(self, mock_read_url, mock_ver):
        mock_read_url.return_value = {'new_version': 42}
        mock_callback = mock.Mock()

        self.version._check_latest_version(mock_callback)

        mock_callback.assert_called_once_with(42)

    @mock.patch('cloudbaseinit.version.get_version')
    @mock.patch('cloudbaseinit.version._read_url')
    def test__check_latest_version_fails(self, mock_read_url, mock_ver):
        mock_read_url.side_effect = Exception('no worky')
        mock_callback = mock.Mock()

        with testutils.LogSnatcher('cloudbaseinit.version') as snatcher:
            self.version._check_latest_version(mock_callback)

        expected_logging = ['Failed checking for new versions: no worky']
        self.assertEqual(expected_logging, snatcher.output)
        self.assertFalse(mock_callback.called)

    @mock.patch('cloudbaseinit.version.get_version')
    @mock.patch('cloudbaseinit.version._read_url')
    def test__check_latest_version_no_content(self, mock_read_url, mock_ver):
        mock_read_url.return_value = None
        mock_callback = mock.Mock()

        self.version._check_latest_version(mock_callback)

        self.assertFalse(mock_callback.called)

    @mock.patch('cloudbaseinit.version.get_version')
    @mock.patch('cloudbaseinit.version._read_url')
    def test__check_latest_version_no_new_version(
            self, mock_read_url, mock_ver):
        mock_read_url.return_value = {'new_versio': 42}
        mock_callback = mock.Mock()

        result = self.version._check_latest_version(mock_callback)

        self.assertFalse(mock_callback.called)
        self.assertIsNone(result)
