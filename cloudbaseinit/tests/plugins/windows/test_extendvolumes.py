# Copyright (c) 2013 Cloudbase Solutions Srl
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

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils


class TestExtendVolumesPlugin(unittest.TestCase):

    def setUp(self):
        self._ctypes_mock = mock.MagicMock()
        self._comtypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'comtypes': self._comtypes_mock,
             'ctypes': self._ctypes_mock})

        self._module_patcher.start()
        self.addCleanup(self._module_patcher.stop)

        extendvolumes = importlib.import_module('cloudbaseinit.plugins.'
                                                'windows.extendvolumes')
        self._extend_volumes = extendvolumes.ExtendVolumesPlugin()

    def test_get_volumes_to_extend(self):
        with testutils.ConfPatcher('volumes_to_extend', '1'):
            response = self._extend_volumes._get_volumes_to_extend()
            self.assertEqual([1], response)

    @mock.patch("cloudbaseinit.utils.windows.storage.factory"
                ".get_storage_manager")
    @mock.patch("cloudbaseinit.plugins.windows.extendvolumes"
                ".ExtendVolumesPlugin._get_volumes_to_extend")
    def test_execute(self, mock_get_volumes_to_extend,
                     mock_get_storage_manager):
        volumes_indexes = [1, 3]
        mock_get_volumes_to_extend.return_value = volumes_indexes
        storage_manager = mock.Mock()
        mock_get_storage_manager.return_value = storage_manager

        response = self._extend_volumes.execute(mock.Mock(), mock.Mock())

        mock_get_volumes_to_extend.assert_called_once_with()
        mock_get_storage_manager.assert_called_once_with()
        storage_manager.extend_volumes.assert_called_once_with(
            volumes_indexes)
        self.assertEqual((base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False),
                         response)
