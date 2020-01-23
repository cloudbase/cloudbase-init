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
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.utils.template_engine.jinja2_template import (
    Jinja2TemplateEngine)


@ddt.ddt
class TestJinja2TemplateEngine(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.template_engine.base_template'
                '.BaseTemplateEngine.remove_template_definition')
    def _test_jinja_render_template(self, mock_remove_header,
                                    fake_instance_data, expected_result,
                                    fake_template = b'{{v1.local_hostname}}'):

        mock_remove_header.return_value = fake_template

        output = Jinja2TemplateEngine().render(fake_instance_data,
                                               fake_template)

        self.assertEqual(expected_result, output)

    def test_jinja_render_template(self):
        fake_instance_data = {
            'v1': {
                'local_hostname': 'fake_hostname'
            }
        }
        expected_result = b'fake_hostname'
        self._test_jinja_render_template(
            fake_instance_data=fake_instance_data,
            expected_result=expected_result)

    def test_jinja_render_template_missing_variable(self):
        fake_instance_data = {
            'v1': {
                'localhostname': 'fake_hostname'
            }
        }
        expected_result = b'CI_MISSING_JINJA_VAR/local_hostname'
        self._test_jinja_render_template(
            fake_instance_data=fake_instance_data,
            expected_result=expected_result)

    def test_jinja_render_template_multiple_variables(self):
        fake_instance_data = {
            'v1': {
                'localhostname': 'fake_hostname'
            },
            'ds': {
                'meta_data': {
                    'hostname': 'fake_hostname'
                },
                'meta-data': {
                    'hostname': 'fake_hostname'
                }
            }
        }
        fake_template = b'{{ds.meta_data.hostname}}'
        expected_result = b'fake_hostname'
        self._test_jinja_render_template(
            fake_instance_data=fake_instance_data,
            expected_result=expected_result,
            fake_template=fake_template)

    @ddt.data((b'', None),
              (None, None),
              (b'## template:jinja \n#ps1 \nmkdir', True),
              (b'## template:jinja test', None),
              (b'## template:jinjanone \ntest', None))
    @ddt.unpack
    def test_load_template_definition(self, userdata, expected_output):
        output = Jinja2TemplateEngine().load(userdata)
        self.assertEqual(expected_output, output)
