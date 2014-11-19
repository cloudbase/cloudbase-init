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
import re
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.tests import testutils


class ExtendVolumesPluginTests(unittest.TestCase):
    def setUp(self):
        self._ctypes_mock = mock.MagicMock()
        self._comtypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'comtypes': self._comtypes_mock,
             'ctypes': self._ctypes_mock})

        self._module_patcher.start()

        extendvolumes = importlib.import_module('cloudbaseinit.plugins.'
                                                'windows.extendvolumes')
        self._extend_volumes = extendvolumes.ExtendVolumesPlugin()

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('cloudbaseinit.plugins.windows.extendvolumes'
                '.ExtendVolumesPlugin._get_volume_index')
    @mock.patch('cloudbaseinit.plugins.windows.extendvolumes'
                '.ExtendVolumesPlugin._extend_volume')
    @mock.patch('cloudbaseinit.utils.windows.vds.IVdsVolume')
    def test_extend_volumes(self, _vds_mock, mock_extend_volume,
                            mock_get_volume_index):
        mock_pack = mock.MagicMock()
        mock_volume_idxs = mock.MagicMock()
        mock_enum = mock.MagicMock()
        mock_unk = mock.MagicMock()
        mock_c = mock.MagicMock()
        mock_volume = mock.MagicMock()
        mock_properties = mock.MagicMock()
        mock_pack.QueryVolumes.return_value = mock_enum
        mock_enum.Next.side_effect = [(mock_unk, mock_c), (None, None)]
        mock_unk.QueryInterface.return_value = mock_volume
        mock_volume.GetProperties.return_value = mock_properties
        self._ctypes_mock.wstring_at.return_value = 'fake name'
        mock_get_volume_index.return_value = mock_volume_idxs
        self._extend_volumes._extend_volumes(mock_pack, [mock_volume_idxs])
        mock_pack.QueryVolumes.assert_called_once_with()
        mock_enum.Next.assert_called_with(1)
        mock_unk.QueryInterface.assert_called_once_with(_vds_mock)
        mock_volume.GetProperties.assert_called_once_with()
        self._ctypes_mock.wstring_at.assert_called_with(
            mock_properties.pwszName)
        mock_get_volume_index.assert_called_once_with('fake name')
        mock_extend_volume.assert_called_once_with(mock_pack, mock_volume,
                                                   mock_properties)
        self._ctypes_mock.windll.ole32.CoTaskMemFree.assert_called_once_with(
            mock_properties.pwszName)

    def test_get_volume_index(self):
        mock_value = mock.MagicMock()
        re.match = mock.MagicMock(return_value=mock_value)
        mock_value.group.return_value = '9999'
        response = self._extend_volumes._get_volume_index('$2')
        mock_value.group.assert_called_once_with(1)
        self.assertTrue(response == 9999)

    @mock.patch('cloudbaseinit.plugins.windows.extendvolumes'
                '.ExtendVolumesPlugin._get_volume_extents_to_resize')
    @mock.patch('cloudbaseinit.utils.windows.vds.VDS_INPUT_DISK')
    def test_extend_volume(self, mock_VDS_INPUT_DISK,
                           mock_get_volume_extents_to_resize):
        mock_disk = mock.MagicMock()
        mock_pack = mock.MagicMock()
        mock_volume = mock.MagicMock()
        mock_properties = mock.MagicMock()
        mock_volume_extent = mock.MagicMock()
        mock_async = mock.MagicMock()
        mock_get_volume_extents_to_resize.return_value = [(mock_volume_extent,
                                                           9999)]
        mock_VDS_INPUT_DISK.return_value = mock_disk
        mock_volume.Extend.return_value = mock_async

        self._extend_volumes._extend_volume(mock_pack, mock_volume,
                                            mock_properties)

        mock_get_volume_extents_to_resize.assert_called_once_with(
            mock_pack, mock_properties.id)
        self._ctypes_mock.wstring_at.assert_called_with(
            mock_properties.pwszName)
        mock_volume.Extend.assert_called_once_with(
            mock_VDS_INPUT_DISK.__mul__()(), 1)
        mock_async.Wait.assert_called_once_with()

    @mock.patch('cloudbaseinit.utils.windows.vds.IVdsDisk')
    @mock.patch('cloudbaseinit.utils.windows.vds.VDS_DISK_EXTENT')
    def test_get_volume_extents_to_resize(self, mock_VDS_DISK_EXTENT,
                                          mock_IVdsDisk):
        mock_pack = mock.MagicMock()
        mock_extents_p = mock.MagicMock()
        mock_unk = mock.MagicMock()
        mock_c = mock.MagicMock()
        mock_disk = mock.MagicMock()
        mock_enum = mock.MagicMock()
        fake_volume_id = '$1'
        mock_array = mock.MagicMock()
        mock_array.volumeId = fake_volume_id
        mock_pack.QueryDisks.return_value = mock_enum
        mock_enum.Next.side_effect = [(mock_unk, mock_c), (None, None)]
        mock_unk.QueryInterface.return_value = mock_disk
        mock_disk.QueryExtents.return_value = (mock_extents_p,
                                               1)
        mock_VDS_DISK_EXTENT.__mul__().from_address.return_value = [mock_array]

        response = self._extend_volumes._get_volume_extents_to_resize(
            mock_pack, fake_volume_id)

        mock_pack.QueryDisks.assert_called_once_with()
        mock_enum.Next.assert_called_with(1)
        mock_unk.QueryInterface.assert_called_once_with(mock_IVdsDisk)
        self._ctypes_mock.addressof.assert_called_with(mock_extents_p.contents)
        mock_VDS_DISK_EXTENT.__mul__().from_address.assert_called_with(
            self._ctypes_mock.addressof(mock_extents_p.contents))

        self._ctypes_mock.pointer.assert_called_once_with(
            mock_VDS_DISK_EXTENT())
        self.assertEqual([], response)

        self._ctypes_mock.windll.ole32.CoTaskMemFree.assert_called_with(
            mock_extents_p)

    @mock.patch('cloudbaseinit.utils.windows.vds.'
                'VDS_QUERY_SOFTWARE_PROVIDERS')
    @mock.patch('cloudbaseinit.utils.windows.vds.IVdsSwProvider')
    def test_query_providers(self, mock_IVdsSwProvider,
                             mock_VDS_QUERY_SOFTWARE_PROVIDERS):
        mock_svc = mock.MagicMock()
        mock_enum = mock.MagicMock()
        mock_unk = mock.MagicMock()
        mock_c = mock.MagicMock()
        mock_svc.QueryProviders.return_value = mock_enum
        mock_enum.Next.side_effect = [(mock_unk, mock_c), (None, None)]
        mock_unk.QueryInterface.return_value = 'fake providers'

        response = self._extend_volumes._query_providers(mock_svc)
        mock_svc.QueryProviders.assert_called_once_with(
            mock_VDS_QUERY_SOFTWARE_PROVIDERS)
        mock_enum.Next.assert_called_with(1)
        mock_unk.QueryInterface.assert_called_once_with(mock_IVdsSwProvider)
        self.assertEqual(['fake providers'], response)

    @mock.patch('cloudbaseinit.utils.windows.vds.IVdsPack')
    def test_query_packs(self, mock_IVdsPack):
        mock_provider = mock.MagicMock()
        mock_enum = mock.MagicMock()
        mock_unk = mock.MagicMock()
        mock_c = mock.MagicMock()
        mock_provider.QueryPacks.return_value = mock_enum
        mock_enum.Next.side_effect = [(mock_unk, mock_c), (None, None)]
        mock_unk.QueryInterface.return_value = 'fake packs'

        response = self._extend_volumes._query_packs(mock_provider)

        mock_provider.QueryPacks.assert_called_once_with()
        mock_enum.Next.assert_called_with(1)
        mock_unk.QueryInterface.assert_called_once_with(mock_IVdsPack)
        self.assertEqual(['fake packs'], response)

    def test_get_volumes_to_extend(self):
        with testutils.ConfPatcher('volumes_to_extend', '1'):
            response = self._extend_volumes._get_volumes_to_extend()
            self.assertEqual([1], response)

    @mock.patch('cloudbaseinit.utils.windows.vds.load_vds_service')
    @mock.patch('cloudbaseinit.plugins.windows.extendvolumes.'
                'ExtendVolumesPlugin._query_providers')
    @mock.patch('cloudbaseinit.plugins.windows.extendvolumes.'
                'ExtendVolumesPlugin._query_packs')
    @mock.patch('cloudbaseinit.plugins.windows.extendvolumes.'
                'ExtendVolumesPlugin._extend_volumes')
    def test_execute(self, mock_extend_volumes, mock_query_packs,
                     mock_query_providers, mock_load_vds_service):
        mock_svc = mock.MagicMock()
        fake_providers = ['fake providers']
        fake_packs = ['fake packs']
        mock_service = mock.MagicMock()
        fake_data = 'fake data'
        mock_load_vds_service.return_value = mock_svc
        mock_query_providers.return_value = fake_providers
        mock_query_packs.return_value = fake_packs

        with testutils.ConfPatcher('volumes_to_extend', '1'):
            self._extend_volumes.execute(mock_service, fake_data)

        mock_query_providers.assert_called_once_with(mock_svc)
        mock_query_packs.assert_called_once_with('fake providers')
        mock_extend_volumes.assert_called_with('fake packs', [1])
