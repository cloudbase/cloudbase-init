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

import time
import unittest
import unittest.mock as mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata import factory
from cloudbaseinit.tests import testutils


CONF = cloudbaseinit_conf.CONF


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

    @mock.patch('cloudbaseinit.metadata.factory.classloader.ClassLoader')
    def _test_parallel_get_metadata_service(self, mock_class_loader,
                                            available_indexes=(1,),
                                            raising_indexes=(),
                                            class_paths=None):
        if class_paths is None:
            class_paths = ['fake.service.%s' % index
                           for index in range(3)]
        CONF.metadata_services = class_paths
        loaded_services = [mock.MagicMock() for _ in class_paths]
        # `load_class(path)()` is what the factory calls, so each provider
        # must be handed out through a callable.
        mock_class_loader.return_value.load_class.side_effect = [
            lambda service=service: service for service in loaded_services]
        for index, service in enumerate(loaded_services):
            if index in raising_indexes:
                service.load.side_effect = Exception
            else:
                service.load.return_value = index in available_indexes

        response = factory.get_metadata_service_parallel()
        expected_index = next((index for index in range(len(class_paths))
                               if index in available_indexes and
                               index not in raising_indexes), None)
        if expected_index is None:
            self.assertIsNone(response)
        else:
            self.assertEqual(loaded_services[expected_index], response)

    def test_get_metadata_service_parallel_first_available(self):
        self._test_parallel_get_metadata_service(available_indexes=(0,))

    def test_get_metadata_service_parallel_last_available(self):
        self._test_parallel_get_metadata_service(available_indexes=(2,))

    def test_get_metadata_service_parallel_prefers_listed_order(self):
        # All providers report success; the earliest listed one must win.
        self._test_parallel_get_metadata_service(
            available_indexes=(0, 1, 2))

    def test_get_metadata_service_parallel_none_available(self):
        with self.assertRaises(exception.MetadataNotFoundException):
            self._test_parallel_get_metadata_service(available_indexes=())

    @mock.patch('cloudbaseinit.metadata.factory.classloader.ClassLoader')
    def _test_parallel_slow_high_priority_provider(self, mock_class_loader):
        """A slow high-priority provider must still beat a fast one.

        The probes run concurrently, so the winner has to be decided by the
        position in `metadata_services` and not by which probe happened to
        answer first.
        """
        class_paths = ['fake.service.%s' % index for index in range(3)]
        CONF.metadata_services = class_paths
        loaded_services = [mock.MagicMock() for _ in class_paths]
        mock_class_loader.return_value.load_class.side_effect = [
            lambda service=service: service for service in loaded_services]

        def load_slow():
            time.sleep(0.2)
            return True

        loaded_services[0].load.side_effect = load_slow
        for service in loaded_services[1:]:
            service.load.return_value = True

        response = factory.get_metadata_service_parallel()
        self.assertEqual(loaded_services[0], response)

    def test_get_metadata_service_parallel_raising_provider_is_skipped(self):
        # A provider that raises must not hide a later available one.
        self._test_parallel_get_metadata_service(
            available_indexes=(1, 2), raising_indexes=(0,))

    @mock.patch('cloudbaseinit.metadata.factory.classloader.ClassLoader')
    def _test_parallel_get_metadata_service_unloadable(self,
                                                       mock_class_loader):
        """A provider whose class cannot be loaded must not break the run."""
        class_paths = ['fake.service.unloadable', 'fake.service.available']
        CONF.metadata_services = list(class_paths)
        available_service = mock.MagicMock()
        available_service.load.return_value = True

        def load_class(path):
            if path == class_paths[0]:
                raise exception.CloudbaseInitException('cannot import')
            return lambda: available_service

        mock_class_loader.return_value.load_class.side_effect = load_class

        response = factory.get_metadata_service_parallel()
        self.assertEqual(available_service, response)

    def test_get_metadata_service_parallel_load_exception(self):
        with testutils.LogSnatcher('cloudbaseinit.metadata.factory') \
                as snatcher:
            self._test_parallel_get_metadata_service_unloadable()
        self.assertEqual(
            ["Failed to load metadata service "
             "'fake.service.unloadable'"], snatcher.output[:1])

    def test_get_metadata_service_parallel_slow_provider_priority(self):
        self._test_parallel_slow_high_priority_provider()

    @testutils.ConfPatcher('parallel', True)
    def test_get_metadata_service_parallel_enabled(self):
        with mock.patch('cloudbaseinit.metadata.factory.'
                        'get_metadata_service_parallel') \
                as mock_parallel:
            factory.get_metadata_service()
            mock_parallel.assert_called_once_with()

    @testutils.ConfPatcher('parallel', False)
    def test_get_metadata_service_parallel_disabled(self):
        with mock.patch('cloudbaseinit.metadata.factory.'
                        'get_metadata_service_sequential') \
                as mock_sequential:
            factory.get_metadata_service()
            mock_sequential.assert_called_once_with()
