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

try:
    import unittest.mock as mock
except ImportError:
    import mock
import unittest

from cloudbaseinit.utils.template_engine import factory


class FakeLoaderError(Exception):
    pass


class TestTemplateFactory(unittest.TestCase):

    def test_get_template_engine_empty(self):
        fake_userdata = b''
        result = factory.get_template_engine(fake_userdata)
        self.assertEqual(result, None)

    def test_get_template_engine_no_match(self):
        fake_userdata = b'no match'
        result = factory.get_template_engine(fake_userdata)
        self.assertEqual(result, None)

    def test_get_template_engine_not_supported(self):
        fake_userdata = b'## template:fake'
        result = factory.get_template_engine(fake_userdata)
        self.assertEqual(result, None)

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader')
    def test_get_template_engine(self, mock_class_loader):
        fake_userdata = b'## template:jinja'
        mock_load_class = mock_class_loader.return_value.load_class
        self.assertEqual(mock_load_class.return_value.return_value,
                         factory.get_template_engine(fake_userdata))

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader')
    def test_get_template_engine_class_not_found(self, mock_class_loader):
        fake_userdata = b'## template:jinja'
        mock_class_loader.return_value.load_class.side_effect = (
            FakeLoaderError)
        self.assertRaises(FakeLoaderError,
                          factory.get_template_engine, fake_userdata)
