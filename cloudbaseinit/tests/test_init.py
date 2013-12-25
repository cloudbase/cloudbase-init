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
import sys

from cloudbaseinit import init
from cloudbaseinit.plugins import base
from cloudbaseinit.openstack.common import cfg

CONF = cfg.CONF
_win32com_mock = mock.MagicMock()
_comtypes_mock = mock.MagicMock()
_pywintypes_mock = mock.MagicMock()
_ctypes_mock = mock.MagicMock()
_ctypes_util_mock = mock.MagicMock()
mock_dict = {'ctypes.util': _ctypes_util_mock,
             'win32com': _win32com_mock,
             'comtypes': _comtypes_mock,
             'pywintypes': _pywintypes_mock,
             'ctypes': _ctypes_mock}


class InitManagerTest(unittest.TestCase):
    @mock.patch.dict(sys.modules, mock_dict)
    def setUp(self):
        self.osutils = mock.MagicMock()
        self.plugin = mock.MagicMock()
        self._init = init.InitManager()

    def tearDown(self):
        reload(sys)
        reload(init)

    def test_get_plugin_status(self):
        self.osutils.get_config_value.return_value = 1
        response = self._init._get_plugin_status(self.osutils, 'fake plugin')
        self.osutils.get_config_value.assert_called_once_with(
            'fake plugin', self._init._PLUGINS_CONFIG_SECTION)
        self.assertTrue(response == 1)

    def test_set_plugin_status(self):

        self._init._set_plugin_status(self.osutils, 'fake plugin', 'status')
        self.osutils.set_config_value.assert_called_once_with(
            'fake plugin', 'status', self._init._PLUGINS_CONFIG_SECTION)

    @mock.patch('cloudbaseinit.init.InitManager._get_plugin_status')
    @mock.patch('cloudbaseinit.init.InitManager._set_plugin_status')
    def _test_exec_plugin(self, status, mock_set_plugin_status,
                          mock_get_plugin_status):
        fake_name = 'fake name'
        self.plugin.get_name.return_value = fake_name
        self.plugin.execute.return_value = (status, True)
        mock_get_plugin_status.return_value = status

        response = self._init._exec_plugin(osutils=self.osutils,
                                           service='fake service',
                                           plugin=self.plugin,
                                           shared_data='shared data')

        mock_get_plugin_status.assert_called_once_with(self.osutils,
                                                       fake_name)
        if status is base.PLUGIN_EXECUTE_ON_NEXT_BOOT:
            self.plugin.execute.assert_called_once_with('fake service',
                                                        'shared data')
            mock_set_plugin_status.assert_called_once_with(self.osutils,
                                                           fake_name, status)
            self.assertTrue(response)

    def test_test_exec_plugin_execution_done(self):
        self._test_exec_plugin(base.PLUGIN_EXECUTION_DONE)

    def test_test_exec_plugin(self):
        self._test_exec_plugin(base.PLUGIN_EXECUTE_ON_NEXT_BOOT)

    def _test_check_plugin_os_requirements(self, requirements):
        sys.platform = 'win32'
        fake_name = 'fake name'
        self.plugin.get_name.return_value = fake_name
        self.plugin.get_os_requirements.return_value = requirements

        response = self._init._check_plugin_os_requirements(self.osutils,
                                                            self.plugin)

        self.plugin.get_name.assert_called_once_with()
        self.plugin.get_os_requirements.assert_called_once_with()
        if requirements[0] == 'win32':
            self.assertTrue(response)
        else:
            self.assertFalse(response)

    def test_check_plugin_os_requirements(self):
        self._test_check_plugin_os_requirements(('win32', (5, 2)))

    def test_check_plugin_os_requirements_other_requirenments(self):
        self._test_check_plugin_os_requirements(('linux', (5, 2)))

    @mock.patch('cloudbaseinit.init.InitManager'
                '._check_plugin_os_requirements')
    @mock.patch('cloudbaseinit.init.InitManager._exec_plugin')
    @mock.patch('cloudbaseinit.plugins.factory.PluginFactory.load_plugins')
    @mock.patch('cloudbaseinit.osutils.factory.OSUtilsFactory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.factory.MetadataServiceFactory.'
                'get_metadata_service')
    def test_configure_host(self, mock_get_metadata_service,
                            mock_get_os_utils, mock_load_plugins,
                            mock_exec_plugin,
                            mock_check_os_requirements):
        fake_service = mock.MagicMock()
        fake_plugin = mock.MagicMock()
        mock_load_plugins.return_value = [fake_plugin]
        mock_get_os_utils.return_value = self.osutils
        mock_get_metadata_service.return_value = fake_service
        fake_service.get_name.return_value = 'fake name'

        self._init.configure_host()

        self.osutils.wait_for_boot_completion.assert_called_once()
        mock_get_metadata_service.assert_called_once_with()
        fake_service.get_name.assert_called_once_with()
        mock_check_os_requirements.assert_called_once_with(self.osutils,
                                                           fake_plugin)
        mock_exec_plugin.assert_called_once_with(self.osutils, fake_service,
                                                 fake_plugin, {})
        fake_service.cleanup.assert_called_once_with()
        self.osutils.reboot.assert_called_once_with()
