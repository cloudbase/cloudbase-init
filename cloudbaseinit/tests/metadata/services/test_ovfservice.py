# Copyright 2019 VMware, Inc.
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

import base64
import importlib
import os
import unittest
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.metadata.services.ovfservice.OvfService"


class OvfServiceTest(unittest.TestCase):

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def setUp(self, mock_osutils):
        self._mock_osutils = mock_osutils
        self._mock_untangle = mock.MagicMock()
        self._mock_ctypes = mock.MagicMock()
        self._mock_wintypes = mock.MagicMock()
        self._moves_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'untangle': self._mock_untangle,
             'ctypes': self._mock_ctypes,
             'ctypes.wintypes': self._mock_wintypes,
             'six.moves': self._moves_mock
             })
        self._module_patcher.start()
        self._ovfservice_module = importlib.import_module(
            'cloudbaseinit.metadata.services.ovfservice')

        self._ovfservice = self._ovfservice_module.OvfService()
        self._logsnatcher = testutils.LogSnatcher(
            'cloudbaseinit.metadata.services.ovfservice')

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('os.path.exists')
    def _test__get_ovf_env_path(self, mock_path_exists,
                                path_exists=True):
        mock_osutils = mock.Mock()
        mock_osutils.get_logical_drives.return_value = ['fake_drive']
        mock_osutils.get_volume_label.return_value = CONF.ovf.drive_label
        mock_path_exists.return_value = path_exists
        self._ovfservice._osutils = mock_osutils

        if not path_exists:
            self.assertRaises(base.NotExistingMetadataException,
                              self._ovfservice._get_ovf_env_path)
        else:
            res = self._ovfservice._get_ovf_env_path()
            ovf_env_path = os.path.join(
                "fake_drive", "ovf-env.xml")
            self.assertEqual(res, ovf_env_path)
            mock_path_exists.assert_called_once_with(ovf_env_path)
        mock_osutils.get_logical_drives.assert_called_once_with()
        mock_osutils.get_volume_label.assert_called_once_with("fake_drive")

    def test_get_ovf_env_path_exists(self):
        self._test__get_ovf_env_path()

    def test_get_ovf_env_path_not_exists(self):
        self._test__get_ovf_env_path(path_exists=False)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_instance_id(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.PropertySection.Property = \
            self._get_test_properties('instance-id')
        res = self._ovfservice.get_instance_id()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, str(id(mock.sentinel.value)))

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_instance_id_unset(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.PropertySection.Property = []
        res = self._ovfservice.get_instance_id()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, 'iid-ovf')

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_decoded_user_data(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.PropertySection.Property = \
            self._get_test_properties('user-data', True)
        res = self._ovfservice.get_decoded_user_data()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, str(id(mock.sentinel.value)).encode())

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_host_name(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.PropertySection.Property = \
            self._get_test_properties('hostname')
        res = self._ovfservice.get_host_name()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, str(id(mock.sentinel.value)))

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_public_keys(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.PropertySection.Property = \
            self._get_test_properties('public-keys')
        res = self._ovfservice.get_public_keys()
        mock_get_ovf_env.assert_called_once_with()
        assert type(res) == list
        assert len(res) == 1
        self.assertEqual(res[0], str(id(mock.sentinel.value)))

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_admin_username(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.PropertySection.Property = \
            self._get_test_properties('username')
        res = self._ovfservice.get_admin_username()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, str(id(mock.sentinel.value)))

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_admin_password(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.PropertySection.Property = \
            self._get_test_properties('password')

        res = self._ovfservice.get_admin_password()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, str(id(mock.sentinel.value)))

    def _get_test_properties(self, property_name, is_encoded=False):
        tested_prop = self._get_tested_property(property_name, is_encoded)
        another_prop = self._get_another_property('AnotherProperty')
        yet_another_prop = self._get_another_property('YetAnotherProperty')
        return [another_prop, tested_prop, yet_another_prop]

    def _get_tested_property(self, property_name, is_encoded):
        if not is_encoded:
            value = str(id(mock.sentinel.value))
        else:
            value = base64.b64encode(str(id(mock.sentinel.value)).encode())

        return {'oe:key': property_name, 'oe:value': value}

    def _get_another_property(self, property_name):
        return {
            'oe:key': property_name,
            'oe:value': str(id(mock.sentinel.another_value))
        }
