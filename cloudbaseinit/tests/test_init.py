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

import sys
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo.config import cfg

from cloudbaseinit import init
from cloudbaseinit.plugins.common import base

CONF = cfg.CONF


class InitManagerTest(unittest.TestCase):

    def setUp(self):
        self._win32com_mock = mock.MagicMock()
        self._comtypes_mock = mock.MagicMock()
        self._pywintypes_mock = mock.MagicMock()
        self._ctypes_mock = mock.MagicMock()
        self._ctypes_util_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes.util': self._ctypes_util_mock,
             'win32com': self._win32com_mock,
             'comtypes': self._comtypes_mock,
             'pywintypes': self._pywintypes_mock,
             'ctypes': self._ctypes_mock})

        self._module_patcher.start()

        self.osutils = mock.MagicMock()
        self.plugin = mock.MagicMock()

        self._init = init.InitManager()

    def tearDown(self):
        self._module_patcher.stop()

    def _test_get_plugin_section(self, instance_id):
        response = self._init._get_plugins_section(instance_id=instance_id)
        if not instance_id:
            self.assertEqual(self._init._PLUGINS_CONFIG_SECTION, response)
        else:
            self.assertEqual(
                instance_id + "/" + self._init._PLUGINS_CONFIG_SECTION,
                response)

    @mock.patch('cloudbaseinit.init.InitManager._get_plugins_section')
    def test_get_plugin_status(self, mock_get_plugins_section):
        self.osutils.get_config_value.return_value = 1
        response = self._init._get_plugin_status(self.osutils, 'fake id',
                                                 'fake plugin')
        mock_get_plugins_section.assert_called_once_with('fake id')
        self.osutils.get_config_value.assert_called_once_with(
            'fake plugin', mock_get_plugins_section())
        self.assertTrue(response == 1)

    @mock.patch('cloudbaseinit.init.InitManager._get_plugins_section')
    def test_set_plugin_status(self, mock_get_plugins_section):
        self._init._set_plugin_status(self.osutils, 'fake id',
                                      'fake plugin', 'status')
        mock_get_plugins_section.assert_called_once_with('fake id')
        self.osutils.set_config_value.assert_called_once_with(
            'fake plugin', 'status', mock_get_plugins_section())

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
                                           instance_id='fake id',
                                           shared_data='shared data')

        mock_get_plugin_status.assert_called_once_with(self.osutils,
                                                       'fake id',
                                                       fake_name)
        if status is base.PLUGIN_EXECUTE_ON_NEXT_BOOT:
            self.plugin.execute.assert_called_once_with('fake service',
                                                        'shared data')
            mock_set_plugin_status.assert_called_once_with(self.osutils,
                                                           'fake id',
                                                           fake_name, status)
            self.assertTrue(response)

    def test_exec_plugin_execution_done(self):
        self._test_exec_plugin(base.PLUGIN_EXECUTION_DONE)

    def test_exec_plugin(self):
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
    @mock.patch('cloudbaseinit.plugins.common.factory.load_plugins')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.factory.get_metadata_service')
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
        fake_service.get_instance_id.return_value = 'fake id'

        self._init.configure_host()

        self.osutils.wait_for_boot_completion.assert_called_once_with()
        mock_get_metadata_service.assert_called_once_with()
        fake_service.get_name.assert_called_once_with()
        mock_check_os_requirements.assert_called_once_with(self.osutils,
                                                           fake_plugin)
        mock_exec_plugin.assert_called_once_with(self.osutils, fake_service,
                                                 fake_plugin, 'fake id', {})
        fake_service.cleanup.assert_called_once_with()
        self.osutils.reboot.assert_called_once_with()
