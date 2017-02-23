# Copyright 2016 Cloudbase Solutions Srl
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
import tempfile
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.utils import classloader


def _create_tempfile():
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    return tmp


class ClassLoaderTest(unittest.TestCase):

    def setUp(self):
        self._loader = classloader.ClassLoader()

    @mock.patch('imp.load_compiled')
    @mock.patch('imp.load_source')
    def test_load_module_py(self, mock_source, mock_compiled):
        mock_py = os.path.join(_create_tempfile(), "mock.py")
        mock_pyc = os.path.join(_create_tempfile(), "mock.pyc")
        mock_source.return_value = mock_compiled.return_value = None
        result_module_py = self._loader.load_module(mock_py)
        result_module_pyc = self._loader.load_module(mock_pyc)
        self.assertIsNone(result_module_py)
        self.assertIsNone(result_module_pyc)
