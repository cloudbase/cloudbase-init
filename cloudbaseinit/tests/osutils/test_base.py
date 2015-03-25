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

import subprocess
import sys
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.osutils import base


class BaseOSUtilsTests(unittest.TestCase):

    def setUp(self):
        self._base = base.BaseOSUtils()

    @mock.patch('sys.stdout')
    @mock.patch('subprocess.Popen')
    @mock.patch('subprocess.PIPE')
    def test_execute_process(self, mock_PIPE, mock_Popen, mock_stdout):
        args = [mock.sentinel.fake_arg]

        mock_p = mock.MagicMock()
        mock_out = mock.MagicMock()
        mock_err = mock.MagicMock()
        mock_Popen.return_value = mock_p
        mock_p.communicate.return_value = (mock_out, mock_err)

        response = self._base.execute_process(args, shell=True,
                                              decode_output=True)

        mock_Popen.assert_called_once_with(args, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, shell=True)
        mock_p.communicate.assert_called_once_with()

        if sys.version_info < (3, 0):
            mock_out.decode.assert_called_once_with(mock_stdout.encoding)
            mock_err.decode.assert_called_once_with(mock_stdout.encoding)
            self.assertEqual((mock_out.decode.return_value,
                              mock_err.decode.return_value, mock_p.returncode),
                             response)
        else:
            self.assertEqual((mock_out, mock_err, mock_p.returncode), response)

    @mock.patch('os.urandom')
    def test_generate_random_password(self, mock_urandom):
        mock_urandom.return_value = b"test"
        response = self._base.generate_random_password(20)

        mock_urandom.assert_called_once_with(256)
        self.assertEqual("dGVzdA==", response)
