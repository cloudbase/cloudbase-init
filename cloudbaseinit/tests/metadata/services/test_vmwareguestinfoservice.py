# Copyright 2020 Cloudbase Solutions Srl
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

import ddt

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


CONF = cloudbaseinit_conf.CONF
BASE_MODULE_PATH = 'cloudbaseinit.metadata.services.vmwareguestinfoservice'
MODULE_PATH = BASE_MODULE_PATH + '.VMwareGuestInfoService'


class FakeException(Exception):
    pass


@ddt.ddt
class VMwareGuestInfoServiceTest(unittest.TestCase):

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def setUp(self, mock_os_utils):
        self._module = importlib.import_module(BASE_MODULE_PATH)
        self._service = (self._module.VMwareGuestInfoService())
        self.snatcher = testutils.LogSnatcher(BASE_MODULE_PATH)

    @ddt.data(((None, False, False), None),
              (('', False, False), None),
              (('dGVzdCANCg==', True, False), b'test \r\n'),
              (('H4sIAAq5MV4CAytR4OUCAGQ5L6gEAAAA', True, True), b't \r\n'),
              )
    @ddt.unpack
    def test_decode_data(self, raw_data, expected_decoded_data):

        decoded_data = self._service._decode_data(raw_data[0], raw_data[1],
                                                  raw_data[2])

        self.assertEqual(decoded_data, expected_decoded_data)

    @mock.patch('os.path.abspath')
    @mock.patch('os.path.exists')
    def _test_load_no_rpc_tool(self, expected_output, rpc_tool_path,
                               mock_path_exists, mock_abs_path):
        CONF.set_override('vmware_rpctool_path', rpc_tool_path,
                          'vmwareguestinfo')
        mock_abs_path.return_value = rpc_tool_path
        mock_path_exists.return_value = False
        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'vmwareguestinfoservice') as snatcher:
            result = self._service.load()
            self.assertEqual(result, False)
            self.assertEqual([expected_output], snatcher.output)

    def test_load_rpc_tool_undefined(self):
        expected_output = ('rpctool_path is empty. '
                           'Please provide a value for VMware rpctool path.')

        self._test_load_no_rpc_tool(expected_output, None)

    def test_load_rpc_tool_not_existent(self):
        expected_output = ('fake_path does not exist. '
                           'Please provide a valid value '
                           'for VMware rpctool path.')

        self._test_load_no_rpc_tool(expected_output, 'fake_path')

    @mock.patch('os.path.exists')
    @mock.patch('cloudbaseinit.utils.serialization.parse_json_yaml')
    @mock.patch(MODULE_PATH + "._get_guest_data")
    def _test_load_meta_data(self, mock_get_guestinfo, mock_parse,
                             mock_os_path_exists, parse_return=None,
                             get_guest_data_result=None, exception=False,
                             expected_result=None, meta_data_return=False):

        mock_os_path_exists.return_value = True
        mock_parse.return_value = parse_return

        if not exception:
            mock_get_guestinfo.return_value = get_guest_data_result
            result = self._service.load()
            self.assertEqual(result, expected_result)
            mock_get_guestinfo.assert_called_with('userdata')
            mock_parse.assert_called_once_with(get_guest_data_result)
            self.assertEqual(mock_get_guestinfo.call_count, 2)
            self.assertEqual(self._service._meta_data, meta_data_return)
            self.assertEqual(self._service._user_data, get_guest_data_result)
        else:
            mock_get_guestinfo.side_effect = FakeException("Fake")
            self.assertRaises(FakeException, self._service.load)

    def test_load_no_meta_data(self):
        self._test_load_meta_data(meta_data_return={})

    def test_load_no_user_data(self):
        parse_return = {"fake": "metadata"}
        self._test_load_meta_data(parse_return=parse_return,
                                  expected_result=True,
                                  meta_data_return=parse_return)

    def test_load_fail(self):
        self._test_load_meta_data(parse_return={"fake": "metadata"},
                                  exception=True)

    def test_load(self):
        parse_return = {"fake": "metadata"}
        self._test_load_meta_data(parse_return=parse_return,
                                  get_guest_data_result="fake userdata",
                                  expected_result=True,
                                  meta_data_return=parse_return)

    def test_load_no_dict_metadata(self):
        self._test_load_meta_data(parse_return="not_a_dict",
                                  expected_result=None, meta_data_return={})

    @ddt.data((None, []),
              ('', []),
              (b'', []),
              (b'ssh1', [b"ssh1"]),
              ('ssh1', ["ssh1"]),
              ('ssh1 ssh2', ["ssh1 ssh2"]),
              ('ssh1 test\nssh2\n', ["ssh1 test", "ssh2"]))
    @ddt.unpack
    def test_get_public_keys(self, keys_data, expected_keys):
        self._service._meta_data = {
            "public-keys-data": keys_data
        }
        public_keys = self._service.get_public_keys()
        public_keys.sort()
        expected_keys.sort()
        self.assertEqual(public_keys, expected_keys)

    @ddt.data((('metadata', ''), (False, False)),
              (('metadata', 'b64'), (True, False)),
              (('metadata', 'base64'), (True, False)),
              (('metadata', 'gzip+base64'), (True, True)),
              (('metadata', 'gz+b64'), (True, True)))
    @ddt.unpack
    @mock.patch(MODULE_PATH + "._decode_data")
    @mock.patch(MODULE_PATH + "._get_guestinfo_value")
    def test_get_guest_data(self, test_data, expected_encoding,
                            mock_get_guestinfo_value,
                            mock_decode_data):

        (data_key, encoding_ret) = test_data
        (is_base64, is_gzip) = expected_encoding
        data_key_ret = 'fake_data'
        decoded_data = 'fake_decoded_data'

        def guest_info_side_effect(*args, **kwargs):
            if args[0] == data_key:
                return data_key_ret
            return encoding_ret

        mock_get_guestinfo_value.side_effect = guest_info_side_effect
        mock_decode_data.return_value = decoded_data

        data = self._service._get_guest_data(data_key)

        self.assertEqual(data, decoded_data)
        mock_decode_data.assert_called_once_with(data_key_ret,
                                                 is_base64, is_gzip)

    @mock.patch(MODULE_PATH + "._get_guestinfo_value")
    def test_get_guest_data_fail(self, mock_get_guestinfo_value):

        mock_get_guestinfo_value.return_value = "no encoding"
        self.assertRaises(exception.CloudbaseInitException,
                          self._service._get_guest_data, 'fake_key')
