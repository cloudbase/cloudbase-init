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

import unittest

import ddt
import yaml

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.utils import serialization


@ddt.ddt
class SerializationUtilsTests(unittest.TestCase):

    @ddt.data((b'', (None, False)),
              (b'{}', ({}, False)),
              (b'---', (None, True)),
              (b'test: test', ({"test": "test"}, True)))
    @ddt.unpack
    @mock.patch("json.loads")
    @mock.patch("yaml.load")
    def test_parse_data(self, stream, expected_parsed_output,
                        mock_yaml_load, mock_json_loads):
        if not expected_parsed_output[1]:
            mock_json_loads.return_value = expected_parsed_output[0]
        else:
            mock_json_loads.side_effect = TypeError("Failed to parse json")
            mock_yaml_load.return_value = expected_parsed_output[0]

        parsed_output = serialization.parse_json_yaml(stream)

        mock_json_loads.assert_called_once_with(stream)
        if expected_parsed_output[1]:
            loader = getattr(yaml, 'CLoader', yaml.Loader)
            mock_yaml_load.assert_called_once_with(stream, Loader=loader)

        self.assertEqual(parsed_output, expected_parsed_output[0])
