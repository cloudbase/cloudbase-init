# Copyright 2015 Cloudbase Solutions Srl
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

from cloudbaseinit import exception


class TestWSMStorageManager(unittest.TestCase):

    def setUp(self):
        self.mock_wmi = mock.MagicMock()

        patcher = mock.patch.dict(
            "sys.modules",
            {
                "wmi": self.mock_wmi
            }
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        wsm_store = importlib.import_module(
            "cloudbaseinit.utils.windows.storage.wsm_storage_manager")
        self.wsm = wsm_store.WSMStorageManager()

    def test_init(self):
        self.mock_wmi.WMI.assert_called_once_with(
            moniker='//./Root/Microsoft/Windows/Storage')

    def _test_extend_volumes(self, extend=True, fail=False,
                             size_ret=0, resize_ret=0):
        volume_indexes = [1, 3]
        volumes = [mock.Mock(), mock.Mock(), mock.Mock()]
        partitions = [mock.Mock()]
        for volume in volumes:
            volume.associators.return_value = partitions
        for partition in partitions:
            size_max = partition.Size = 100
            if extend:
                size_max = partition.Size + 10
            partition.GetSupportedSize.return_value = [
                size_ret,
                mock.Mock(),
                size_max,
                mock.Mock()]
            partition.Resize.return_value = [
                resize_ret,
                mock.Mock()]

        conn = self.mock_wmi.WMI.return_value
        conn.MSFT_Volume.return_value = volumes

        if fail:
            if size_ret or extend:
                with self.assertRaises(exception.CloudbaseInitException):
                    self.wsm.extend_volumes(volume_indexes=volume_indexes)
            return
        self.wsm.extend_volumes(volume_indexes=volume_indexes)

        conn.MSFT_Volume.assert_called_once_with()
        for idx in volume_indexes:
            volumes[idx - 1].associators.assert_called_once_with(
                wmi_result_class='MSFT_Partition')
        volumes[1].associators.assert_not_called()
        for partition in partitions:
            calls = [mock.call()] * len(volume_indexes)
            partition.GetSupportedSize.assert_has_calls(calls)

        if not extend:
            for partition in partitions:
                partition.Resize.assert_not_called()
            return
        for partition in partitions:
            size_max = partition.GetSupportedSize.return_value[2]
            calls = [mock.call(size_max)] * len(volume_indexes)
            partition.Resize.assert_has_calls(calls)

    def test_extend_volumes_fail_size(self):
        self._test_extend_volumes(fail=True, size_ret=1)

    def test_extend_volumes_fail_resize(self):
        self._test_extend_volumes(fail=True, resize_ret=1)

    def test_extend_volumes_no_extend(self):
        self._test_extend_volumes(extend=False)

    def test_extend_volumes(self):
        self._test_extend_volumes()
