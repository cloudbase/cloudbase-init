# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions Srl
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

import mock
import unittest

from cloudbaseinit import exception
from cloudbaseinit.metadata import factory


class MetadataServiceFactoryTests(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def _test_get_metadata_service(self, mock_load_class, ret_value):
        mock_load_class.side_effect = ret_value
        if ret_value is exception.CloudbaseInitException:
            self.assertRaises(exception.CloudbaseInitException,
                              factory.get_metadata_service)
        else:
            response = factory.get_metadata_service()
            self.assertEqual(mock_load_class()(), response)

    def test_get_metadata_service(self):
        m = mock.MagicMock()
        self._test_get_metadata_service(ret_value=m)

    def test_get_metadata_service_exception(self):
        self._test_get_metadata_service(
            ret_value=exception.CloudbaseInitException)
