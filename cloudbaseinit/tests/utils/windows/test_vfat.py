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
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils.windows import vfat

CONF = vfat.CONF


class TestVfat(unittest.TestCase):

    def _test_is_vfat_drive(self, execute_process_value,
                            expected_logging,
                            expected_response):

        mock_osutils = mock.Mock()
        mock_osutils.execute_process.return_value = execute_process_value

        with testutils.LogSnatcher('cloudbaseinit.utils.windows.'
                                   'vfat') as snatcher:
            with testutils.ConfPatcher('mtools_path', 'mtools_path'):

                response = vfat.is_vfat_drive(mock_osutils,
                                              mock.sentinel.drive)

                mdir = os.path.join(CONF.mtools_path, "mlabel.exe")
                mock_osutils.execute_process.assert_called_once_with(
                    [mdir, "-i", mock.sentinel.drive, "-s"],
                    shell=False)

        self.assertEqual(expected_logging, snatcher.output)
        self.assertEqual(expected_response, response)

    def test_is_vfat_drive_fails(self):
        test_stderr = b"test stderr"

        expected_logging = [
            "Could not retrieve label for VFAT drive path %r"
            % (mock.sentinel.drive),
            "mlabel failed with error %r" % test_stderr,
        ]
        execute_process_value = (None, test_stderr, 1)
        expected_response = False

        self._test_is_vfat_drive(execute_process_value=execute_process_value,
                                 expected_logging=expected_logging,
                                 expected_response=expected_response)

    def test_is_vfat_drive_different_label(self):
        mock_out = b"Volume label is config"
        expected_logging = [
            "Obtained label information for drive %r: %r"
            % (mock.sentinel.drive, mock_out)
        ]
        execute_process_value = (mock_out, None, 0)
        expected_response = False

        self._test_is_vfat_drive(execute_process_value=execute_process_value,
                                 expected_logging=expected_logging,
                                 expected_response=expected_response)

    def test_is_vfat_drive_works(self):
        mock_out = b"Volume label is config-2   \r\n"
        expected_logging = [
            "Obtained label information for drive %r: %r"
            % (mock.sentinel.drive, mock_out)
        ]
        execute_process_value = (mock_out, None, 0)
        expected_response = True

        self._test_is_vfat_drive(execute_process_value=execute_process_value,
                                 expected_logging=expected_logging,
                                 expected_response=expected_response)

    def test_is_vfat_drive_works_uppercase(self):
        mock_out = b"Volume label is CONFIG-2   \r\n"
        expected_logging = [
            "Obtained label information for drive %r: %r"
            % (mock.sentinel.drive, mock_out)
        ]
        execute_process_value = (mock_out, None, 0)
        expected_response = True

        self._test_is_vfat_drive(execute_process_value=execute_process_value,
                                 expected_logging=expected_logging,
                                 expected_response=expected_response)

    def test_is_vfat_drive_with_wrong_label(self):
        mock_out = b"Not volu label  \r\n"
        expected_logging = [
            "Obtained label information for drive %r: %r"
            % (mock.sentinel.drive, mock_out)
        ]
        execute_process_value = (mock_out, None, 0)
        expected_response = False

        self._test_is_vfat_drive(execute_process_value=execute_process_value,
                                 expected_logging=expected_logging,
                                 expected_response=expected_response)

    @testutils.ConfPatcher('mtools_path', 'mtools_path')
    @mock.patch('os.chdir')
    def test_copy(self, mock_os_chdir):
        cwd = os.getcwd()
        mock_osutils = mock.Mock()

        vfat.copy_from_vfat_drive(mock_osutils,
                                  mock.sentinel.drive,
                                  mock.sentinel.target_path)

        mock_os_chdir_calls = [
            mock.call(mock.sentinel.target_path),
            mock.call(cwd),
        ]
        self.assertEqual(mock_os_chdir_calls, mock_os_chdir.mock_calls)
        self.assertEqual(os.getcwd(), cwd)

        mcopy = os.path.join(CONF.mtools_path, "mcopy.exe")
        mock_osutils.execute_process.assert_called_once_with(
            [mcopy, "-s", "-n", "-i", mock.sentinel.drive, "::/", "."],
            shell=False)

    def test_is_vfat_drive_mtools_not_given(self):
        with self.assertRaises(exception.CloudbaseInitException) as cm:
            vfat.is_vfat_drive(mock.sentinel.osutils,
                               mock.sentinel.target_path)
        expected_message = ('"mtools_path" needs to be provided in order '
                            'to access VFAT drives')
        self.assertEqual(expected_message, str(cm.exception.args[0]))

    def test_copy_from_vfat_drive_mtools_not_given(self):
        with self.assertRaises(exception.CloudbaseInitException) as cm:
            vfat.copy_from_vfat_drive(mock.sentinel.osutils,
                                      mock.sentinel.drive_path,
                                      mock.sentinel.target_path)
        expected_message = ('"mtools_path" needs to be provided in order '
                            'to access VFAT drives')
        self.assertEqual(expected_message, str(cm.exception.args[0]))
