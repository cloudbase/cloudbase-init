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


from cloudbaseinit.utils import serialization

YAML_PARSER_ERROR_STRING = b"""
a: b
- c: d
"""


@ddt.ddt
class SerializationUtilsTests(unittest.TestCase):

    @ddt.data((b'', (None, True)),
              (b'{}', ({}, True)),
              (YAML_PARSER_ERROR_STRING, (None, False)),
              (b'{}}', (None, False)),
              (b'---', (None, True)),
              (b'test: test', ({"test": "test"}, True)))
    @ddt.unpack
    def test_parse_data(self, stream, expected_parsed_output,
                        ):
        print(expected_parsed_output)
        if expected_parsed_output[1]:
            parsed_output = serialization.parse_json_yaml(stream)
            self.assertEqual(parsed_output, expected_parsed_output[0])
        else:
            with self.assertRaises(serialization.YamlParserConfigError):
                serialization.parse_json_yaml(stream)
