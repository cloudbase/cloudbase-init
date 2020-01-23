# Copyright 2019 Cloudbase Solutions Srl
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

import ddt
import unittest

from cloudbaseinit.utils.template_engine import base_template as bt


@ddt.ddt
class TestBaseTemplateEngine(unittest.TestCase):

    @ddt.data((b'', b''),
              (None, None),
              (b'## template:jinja test', b''),
              (b'## template:jinja \ntest', b'test'))
    @ddt.unpack
    def test_remove_template_definition(self, template, expected_output):
        output = bt.BaseTemplateEngine.remove_template_definition(template)
        self.assertEqual(expected_output, output)
