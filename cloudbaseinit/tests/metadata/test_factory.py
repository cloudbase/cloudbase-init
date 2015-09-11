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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.metadata import factory
from cloudbaseinit.tests import testutils


class MetadataServiceFactoryTests(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def _test_get_metadata_service(self, mock_load_class,
                                   ret_value=mock.MagicMock(),
                                   load_exception=False):
        mock_load_class.side_effect = ret_value
        if load_exception:
            mock_load_class()().load.side_effect = Exception
            with self.assertRaises(exception.CloudbaseInitException):
                factory.get_metadata_service()
            return
        if ret_value is exception.CloudbaseInitException:
            self.assertRaises(exception.CloudbaseInitException,
                              factory.get_metadata_service)
        else:
            response = factory.get_metadata_service()
            self.assertEqual(mock_load_class()(), response)

    def test_get_metadata_service(self):
        self._test_get_metadata_service()

    def test_get_metadata_service_exception(self):
        self._test_get_metadata_service(
            ret_value=exception.CloudbaseInitException)

    def test_get_metadata_service_load_exception(self):
        with testutils.LogSnatcher('cloudbaseinit.metadata.'
                                   'factory'):
            self._test_get_metadata_service(load_exception=True)
