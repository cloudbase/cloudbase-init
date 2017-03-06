# Copyright (c) 2017 Cloudbase Solutions Srl
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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base as metadata_services_base
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import ephemeraldisk
from cloudbaseinit.tests import testutils


CONF = cloudbaseinit_conf.CONF
MODULE_PATH = 'cloudbaseinit.plugins.common.ephemeraldisk'


class TestEphemeralDiskPlugin(unittest.TestCase):

    def setUp(self):
        self._disk = ephemeraldisk.EphemeralDiskPlugin()

    def _test_get_ephemeral_disk_volume_by_mount_point(self, mount_point,
                                                       paths, exception_raise):
        mock_osutils = mock.MagicMock()
        eclass = exception.ItemNotFoundException
        if exception_raise:
            mock_osutils.get_volume_path_names_by_mount_point.side_effect = \
                eclass()
        else:
            mock_osutils.get_volume_path_names_by_mount_point.return_value = \
                paths

        with testutils.ConfPatcher('ephemeral_disk_volume_mount_point',
                                   mount_point):
            if exception_raise:
                with testutils.LogSnatcher(MODULE_PATH) as snatcher:
                    self._disk._get_ephemeral_disk_volume_by_mount_point(
                        mock_osutils)
                expected_logging = [
                    "Ephemeral disk mount point not found: %s" % mount_point
                ]
            else:
                result = None
                result = self._disk._get_ephemeral_disk_volume_by_mount_point(
                    mock_osutils)
        if mount_point:
            (mock_osutils.get_volume_path_names_by_mount_point.
                assert_called_once_with(str(mount_point)))
            if not exception_raise:
                if paths:
                    self.assertEqual(result, paths[0])
                else:
                    self.assertEqual(result, None)
            else:
                self.assertEqual(snatcher.output, expected_logging)

    def test_get_ephemeral_disk_volume_by_mount_point_no_mount_point(self):
        self._test_get_ephemeral_disk_volume_by_mount_point(
            mount_point=None, paths=None, exception_raise=False)

    def test_get_ephemeral_disk_volume_by_mount_point_no_paths(self):
        self._test_get_ephemeral_disk_volume_by_mount_point(
            mount_point=True, paths=None, exception_raise=False)

    def test_get_ephemeral_disk_volume_by_mount_point_exception(self):
        self._test_get_ephemeral_disk_volume_by_mount_point(
            mount_point=True, paths=None, exception_raise=True)

    def test_get_ephemeral_disk_volume_by_mount_point(self):
        self._test_get_ephemeral_disk_volume_by_mount_point(
            mount_point=True, paths=[mock.sentinel.paths],
            exception_raise=False)

    def _test_get_ephemeral_disk_volume_by_label(self, label,
                                                 ephemeral_disk_volume_label):
        expected_result = None
        mock_osutils = mock.MagicMock()
        if ephemeral_disk_volume_label:
            labels = [None, str(mock.sentinel.label)] * 2
            labels += [label] + [None, str(mock.sentinel.label)]
            mock_osutils.get_logical_drives.return_value = range(len(labels))
            mock_osutils.get_volume_label.side_effect = labels
            if label.upper() == ephemeral_disk_volume_label.upper():
                expected_result = labels.index(label)
        with testutils.ConfPatcher('ephemeral_disk_volume_label',
                                   ephemeral_disk_volume_label):
            result = self._disk._get_ephemeral_disk_volume_by_label(
                mock_osutils)
        self.assertEqual(result, expected_result)
        if ephemeral_disk_volume_label:
            mock_osutils.get_logical_drives.assert_called_once_with()
            if expected_result is not None:
                self.assertEqual(mock_osutils.get_volume_label.call_count,
                                 expected_result + 1)
            else:
                self.assertEqual(mock_osutils.get_volume_label.call_count,
                                 len(labels))

    def test_get_ephemeral_disk_volume_by_label_no_disk_volume_label(self):
        self._test_get_ephemeral_disk_volume_by_label(
            label=None, ephemeral_disk_volume_label=None)

    def test_get_ephemeral_disk_volume_by_label_no_label(self):
        self._test_get_ephemeral_disk_volume_by_label(
            label=str(mock.sentinel.label),
            ephemeral_disk_volume_label=str(mock.sentinel.disk_volume_label))

    def test_get_ephemeral_disk_volume_by_label(self):
        self._test_get_ephemeral_disk_volume_by_label(
            label=str(mock.sentinel.same_label),
            ephemeral_disk_volume_label=str(mock.sentinel.same_label))

    @mock.patch.object(ephemeraldisk.EphemeralDiskPlugin,
                       '_get_ephemeral_disk_volume_by_label')
    @mock.patch.object(ephemeraldisk.EphemeralDiskPlugin,
                       '_get_ephemeral_disk_volume_by_mount_point')
    def _test_get_ephemeral_disk_volume_path(self, mock_by_mount_point,
                                             mock_by_label,
                                             by_mount_point, by_label):
        mock_osutils = mock.MagicMock()
        mock_by_mount_point.return_value = by_mount_point
        mock_by_label.return_value = by_label
        result = self._disk._get_ephemeral_disk_volume_path(mock_osutils)
        if by_mount_point:
            expected_result = mock_by_mount_point.return_value
        elif by_label:
            expected_result = mock_by_label.return_value
        else:
            expected_result = None

        self.assertEqual(result, expected_result)
        mock_by_mount_point.assert_called_once_with(mock_osutils)
        if not by_mount_point:
            mock_by_label.assert_called_once_with(mock_osutils)

    def test_get_ephemeral_disk_volume_path_by_mount_point(self):
        self._test_get_ephemeral_disk_volume_path(
            by_mount_point=True, by_label=True)

    def test_get_ephemeral_disk_volume_path_by_label(self):
        self._test_get_ephemeral_disk_volume_path(
            by_mount_point=None, by_label=True)

    def test_get_ephemeral_disk_volume_path_None(self):
        self._test_get_ephemeral_disk_volume_path(
            by_mount_point=None, by_label=None)

    def _test_set_ephemeral_disk_data_loss_warning(self, exception_raised):
        mock_service = mock.MagicMock()
        disk_warning_path = str(mock.sentinel.disk_warning_path)
        expected_logging = [
            "Setting ephemeral disk data loss warning: %s" % disk_warning_path
        ]
        if exception_raised:
            eclass = metadata_services_base.NotExistingMetadataException
            mock_service.get_ephemeral_disk_data_loss_warning.side_effect = \
                eclass
            expected_logging += [
                "Metadata service does not provide an ephemeral "
                "disk data loss warning content"
            ]
        else:
            mock_service.get_ephemeral_disk_data_loss_warning.return_value = \
                str(mock.sentinel.data_loss_warning)
        with testutils.LogSnatcher(MODULE_PATH) as snatcher:
            with mock.patch(MODULE_PATH + '.open', mock.mock_open(),
                            create=True) as mock_open:
                self._disk._set_ephemeral_disk_data_loss_warning(
                    mock_service, disk_warning_path)
        self.assertEqual(snatcher.output, expected_logging)
        mock_open.assert_called_once_with(disk_warning_path, 'wb')

    def test_set_ephemeral_disk_data_loss_warning(self):
        self._test_set_ephemeral_disk_data_loss_warning(exception_raised=False)

    def test_set_ephemeral_disk_data_loss_warning_exception(self):
        self._test_set_ephemeral_disk_data_loss_warning(exception_raised=True)

    @mock.patch('os.path.join')
    @mock.patch.object(ephemeraldisk.EphemeralDiskPlugin,
                       '_set_ephemeral_disk_data_loss_warning')
    @mock.patch.object(ephemeraldisk.EphemeralDiskPlugin,
                       '_get_ephemeral_disk_volume_path')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.plugins.common.base.PLUGIN_EXECUTION_DONE',
                mock.sentinel)
    def _test_execute(self, mock_get_osutils, mock_get_volume_path,
                      mock_set_volume_path, mock_join,
                      not_existing_exception, disk_volume_path,
                      disk_warning_path):
        mock_service = mock.MagicMock()
        shared_data = mock.sentinel.shared_data
        eclass = metadata_services_base.NotExistingMetadataException
        expected_result = base.PLUGIN_EXECUTION_DONE, False
        expected_logging = []
        if not_existing_exception:
            mock_service.get_ephemeral_disk_data_loss_warning.side_effect = \
                eclass()

        else:
            mock_osutils = mock.MagicMock()
            mock_get_osutils.return_value = mock_osutils
            mock_get_volume_path.return_value = disk_volume_path
            if not disk_volume_path:
                expected_logging += [
                    "Ephemeral disk volume not found"
                ]
            else:
                mock_join.return_value = disk_warning_path
        with testutils.ConfPatcher('ephemeral_disk_data_loss_warning_path',
                                   disk_warning_path):
            with testutils.LogSnatcher(MODULE_PATH) as snatcher:
                result = self._disk.execute(mock_service, shared_data)
        self.assertEqual(result, expected_result)
        self.assertEqual(snatcher.output, expected_logging)
        (mock_service.get_ephemeral_disk_data_loss_warning.
            assert_called_once_with())
        if not not_existing_exception:
            mock_get_osutils.assert_called_once_with()
            mock_get_volume_path.assert_called_once_with(mock_osutils)
            if disk_volume_path and disk_warning_path:
                mock_join.assert_called_once_with(
                    disk_volume_path, disk_warning_path)
                mock_set_volume_path.assert_called_once_with(
                    mock_service, disk_warning_path)

    def test_execute_no_metadata(self):
        self._test_execute(not_existing_exception=True, disk_volume_path=None,
                           disk_warning_path=None)

    def test_execute_no_ephemeral_disk_volume_path(self):
        self._test_execute(not_existing_exception=None, disk_volume_path=None,
                           disk_warning_path=None)

    def test_execute_no_ephemeral_disk_data_loss_warning_path(self):
        self._test_execute(
            not_existing_exception=None,
            disk_volume_path=str(mock.sentinel.disk_volume_path),
            disk_warning_path=None)

    def test_execute(self):
        self._test_execute(
            not_existing_exception=None,
            disk_volume_path=str(mock.sentinel.disk_volume_path),
            disk_warning_path=str(mock.sentinel.path))

    def test_get_os_requirements(self):
        result = self._disk.get_os_requirements()
        self.assertEqual(result, ('win32', (5, 2)))
