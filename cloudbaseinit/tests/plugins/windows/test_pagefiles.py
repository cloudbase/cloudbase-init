# Copyright 2017 Cloudbase Solutions Srl
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

import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.windows import pagefiles
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.plugins.windows.pagefiles.PageFilesPlugin"


class PageFilesPluginTest(unittest.TestCase):

    def setUp(self):
        self._pagefiles = pagefiles.PageFilesPlugin()
        self._logsnatcher = testutils.LogSnatcher("cloudbaseinit.plugins"
                                                  ".windows.pagefiles")

    def _test_get_page_file_volumes_by_mount_point(
            self, mount_points=None, paths=None,
            get_endpoint_side_effect=False):
        mock_osutils = mock.MagicMock()
        mock_get_volume = mock_osutils.get_volume_path_names_by_mount_point
        if get_endpoint_side_effect:
            mock_get_volume.side_effect = exception.ItemNotFoundException
        else:
            mock_get_volume.return_value = paths
        if not mount_points:
            res = self._pagefiles._get_page_file_volumes_by_mount_point(
                mock_osutils)
            self.assertEqual(res, [])
            return
        with testutils.ConfPatcher("page_file_volume_mount_points",
                                   mount_points):
            if not paths:
                expected_logging = ("Mount point not found: %s"
                                    % mount_points[0])
                with self._logsnatcher:
                    res = (self._pagefiles.
                           _get_page_file_volumes_by_mount_point(mock_osutils))
                self.assertEqual(self._logsnatcher.output[0], expected_logging)
                return
            res = self._pagefiles._get_page_file_volumes_by_mount_point(
                mock_osutils)
            self.assertEqual(res, paths)

    def test_get_page_file_volumes_by_mount_point_no_mount_point(self):
        self._test_get_page_file_volumes_by_mount_point(mount_points=[])

    def test_get_page_file_volumes_by_mount_point_no_endpoint(self):
        mount_points = [mock.sentinel.path]
        self._test_get_page_file_volumes_by_mount_point(
            mount_points=mount_points, get_endpoint_side_effect=True)

    def test_get_page_file_volumes_by_mount_point(self):
        mount_points = [mock.sentinel.path]
        paths = [mock.sentinel.file_path]
        self._test_get_page_file_volumes_by_mount_point(
            mount_points=mount_points, paths=paths)

    def _test_get_page_file_volumes_by_label(self, drives=None,
                                             labels=None, conf_labels=None):
        mock_osutils = mock.MagicMock()
        mock_osutils.get_logical_drives.return_value = drives
        mock_osutils.get_volume_label.return_value = labels
        if not labels:
            res = self._pagefiles._get_page_file_volumes_by_label(mock_osutils)
            self.assertEqual(res, [])
            return
        with testutils.ConfPatcher("page_file_volume_labels",
                                   conf_labels):
            res = self._pagefiles._get_page_file_volumes_by_label(mock_osutils)
            self.assertEqual(res, drives)

    def test_get_page_file_volumes_by_label_no_labels(self):
        mock_drives = [mock.sentinel.fake_drive]
        self._test_get_page_file_volumes_by_label(drives=mock_drives)

    def test_get_page_file_volumes_by_label_drive_found(self):
        fake_label = "fake_label"
        mock_drives = [mock.sentinel.fake_drive]
        mock_labels = fake_label
        mock_conf_labels = [fake_label]
        self._test_get_page_file_volumes_by_label(drives=mock_drives,
                                                  labels=mock_labels,
                                                  conf_labels=mock_conf_labels)

    @mock.patch(MODPATH + "._get_page_file_volumes_by_label")
    @mock.patch(MODPATH + "._get_page_file_volumes_by_mount_point")
    def test_get_page_file_volumes(self, mock_get_by_mount_point,
                                   mock_get_by_label):
        mock_osutils = mock.MagicMock()
        mock_get_by_mount_point.return_value = [mock.sentinel.path_mount]
        mock_get_by_label.return_value = [mock.sentinel.path_label]
        self._pagefiles._get_page_file_volumes(mock_osutils)
        mock_get_by_label.assert_called_once_with(mock_osutils)
        mock_get_by_mount_point.assert_called_once_with(mock_osutils)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch(MODPATH + "._get_page_file_volumes")
    def _test_execute(self, mock_get_page_file_volumes,
                      mock_get_os_utils, file_volumes=None,
                      get_page_files_res=None):
        mock_service = mock.Mock()
        mock_shared_data = mock.Mock()
        mock_osutils = mock.Mock()
        mock_get_os_utils.return_value = mock_osutils
        mock_get_page_file_volumes.return_value = file_volumes
        mock_osutils.get_page_files.return_value = get_page_files_res
        mock_osutils.set_page_files.return_value = file_volumes
        if not file_volumes:
            expected_res = (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)
            expected_logging = [
                "No page file volume found, skipping configuration"]
            with self._logsnatcher:
                res = self._pagefiles.execute(mock_service, mock_shared_data)

            self.assertEqual(res, expected_res)
            self.assertEqual(self._logsnatcher.output, expected_logging)
            mock_get_page_file_volumes.assert_called_once_with(mock_osutils)
            return
        with self._logsnatcher:
            expected_file = [
                (os.path.join(file_volumes[0], "pagefile.sys"), 0, 0)]
            expected_logging = [
                "Page file configuration set: %s" % expected_file]
            expected_res = (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, True)
            res = self._pagefiles.execute(mock_service, mock_shared_data)
        self.assertEqual(res, expected_res)
        self.assertEqual(self._logsnatcher.output, expected_logging)
        mock_osutils.get_page_files.assert_called_once_with()
        mock_osutils.set_page_files.assert_called_once_with(expected_file)

    def test_execute_no_page_file(self):
        self._test_execute(file_volumes=[])

    def test_execute_page_files_found(self):
        mock_file_volumes = [str(mock.sentinel.fake_file)]
        self._test_execute(file_volumes=mock_file_volumes,
                           get_page_files_res=[])

    def test_get_os_requirements(self):
        res = self._pagefiles.get_os_requirements()
        expected_res = ('win32', (5, 2))
        self.assertEqual(res, expected_res)
