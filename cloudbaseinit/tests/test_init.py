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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import init
from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class TestInitManager(unittest.TestCase):

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

    def test_get_plugin_section_id(self):
        fake_id = "100"
        self._test_get_plugin_section(instance_id=fake_id)

    def test_get_plugin_section_no_id(self):
        self._test_get_plugin_section(instance_id=None)

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

    def test_exec_plugin_exception_occurs(self):
        fake_name = 'fake name'
        mock_plugin = mock.MagicMock()
        mock_plugin.get_name.return_value = fake_name
        mock_plugin.execute.side_effect = Exception
        expected_logging = ["Executing plugin 'fake name'",
                            "plugin 'fake name' failed with error ''"]
        with testutils.LogSnatcher('cloudbaseinit.init') as snatcher:
            self._init._exec_plugin(osutils=self.osutils,
                                    service='fake service',
                                    plugin=mock_plugin,
                                    instance_id='fake id',
                                    shared_data='shared data')
        self.assertEqual(expected_logging, snatcher.output[:2])

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

    def test_check_plugins_os_not_min_os_version(self):
        sys.platform = 'win32'
        fake_name = 'fake name'
        self.plugin.get_name.return_value = fake_name
        self.plugin.get_os_requirements.return_value = ('win32', 0)
        response = self._init._check_plugin_os_requirements(self.osutils,
                                                            self.plugin)
        self.plugin.get_name.assert_called_once_with()
        self.assertTrue(response)

    def test_check_plugins_os_not_supported(self):
        fake_name = 'fake name'
        self.plugin.get_name.return_value = fake_name
        mock_osutils = mock.MagicMock()
        mock_osutils.check_os_version.return_value = None
        self.plugin.get_os_requirements.return_value = ('win32', (5, 2))
        response = self._init._check_plugin_os_requirements(mock_osutils,
                                                            self.plugin)
        self.assertFalse(response)

    @mock.patch('cloudbaseinit.init.InitManager.'
                '_exec_plugin')
    @mock.patch('cloudbaseinit.init.InitManager.'
                '_check_plugin_os_requirements')
    @mock.patch('cloudbaseinit.plugins.factory.load_plugins')
    def _test_handle_plugins_stage(self, mock_load_plugins,
                                   mock_check_plugin_os_requirements,
                                   mock_exec_plugin,
                                   reboot=True, fast_reboot=True,
                                   success=True):
        stage = "fake stage"
        service, instance_id = mock.Mock(), mock.Mock()
        plugins = [mock.Mock() for _ in range(3)]
        mock_check_plugin_os_requirements.return_value = True
        mock_exec_plugin.return_value = success, reboot
        mock_load_plugins.return_value = plugins
        requirements_calls = [mock.call(self.osutils, plugin)
                              for plugin in plugins]
        exec_plugin_calls = [mock.call(self.osutils, service, plugin,
                                       instance_id, {})
                             for plugin in plugins]

        with testutils.LogSnatcher('cloudbaseinit.init') as snatcher:
            response = self._init._handle_plugins_stage(
                self.osutils, service, instance_id, stage)
        self.assertEqual(
            ["Executing plugins for stage '{}':".format(stage)],
            snatcher.output)
        mock_load_plugins.assert_called_once_with(stage)
        idx = 1 if (reboot and fast_reboot) else len(plugins)
        mock_check_plugin_os_requirements.assert_has_calls(
            requirements_calls[:idx])
        mock_exec_plugin.assert_has_calls(exec_plugin_calls[:idx])
        self.assertEqual((success, reboot), response)

    def test_handle_plugins_stage(self):
        self._test_handle_plugins_stage()

    def test_handle_plugins_stage_no_reboot(self):
        self._test_handle_plugins_stage(reboot=False, fast_reboot=False)

    @testutils.ConfPatcher('allow_reboot', False)
    def test_handle_plugins_stage_no_fast_reboot(self):
        self._test_handle_plugins_stage(fast_reboot=False)

    def test_handle_plugins_stage_stage_fails(self):
        self._test_handle_plugins_stage(success=False)

    @mock.patch('cloudbaseinit.init.InitManager.'
                '_reset_service_password_and_respawn')
    @mock.patch('cloudbaseinit.init.InitManager'
                '._handle_plugins_stage')
    @mock.patch('cloudbaseinit.init.InitManager._check_latest_version')
    @mock.patch('cloudbaseinit.version.get_version')
    @mock.patch('cloudbaseinit.plugins.factory.load_plugins')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.metadata.factory.get_metadata_service')
    def _test_configure_host(self, mock_get_metadata_service,
                             mock_get_os_utils, mock_load_plugins,
                             mock_get_version, mock_check_latest_version,
                             mock_handle_plugins_stage, mock_reset_service,
                             expected_logging,
                             version, name, instance_id, reboot=True,
                             last_stage=False):
        sys.platform = 'win32'
        mock_get_version.return_value = version
        fake_service = mock.MagicMock()
        fake_plugin = mock.MagicMock()
        mock_load_plugins.return_value = [fake_plugin]
        mock_get_os_utils.return_value = self.osutils
        mock_get_metadata_service.return_value = fake_service
        fake_service.get_name.return_value = name
        fake_service.get_instance_id.return_value = instance_id
        mock_handle_plugins_stage.side_effect = [(True, False), (True, False),
                                                 (last_stage, True)]
        stages = [
            base.PLUGIN_STAGE_PRE_NETWORKING,
            base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY,
            base.PLUGIN_STAGE_MAIN]
        stage_calls_list = [[self.osutils, None, None, stage]
                            for stage in stages]
        stage_calls_list[2][1] = fake_service
        stage_calls_list[2][2] = instance_id
        stage_calls = [mock.call(*args) for args in stage_calls_list]
        with testutils.LogSnatcher('cloudbaseinit.init') as snatcher:
            self._init.configure_host()
        self.assertEqual(expected_logging, snatcher.output)
        mock_check_latest_version.assert_called_once_with()
        if CONF.reset_service_password:
            mock_reset_service.assert_called_once_with(self.osutils)
        if last_stage:
            fake_service.provisioning_completed.assert_called_once_with()

        self.osutils.wait_for_boot_completion.assert_called_once_with()
        mock_get_metadata_service.assert_called_once_with()
        fake_service.get_name.assert_called_once_with()
        fake_service.get_instance_id.assert_called_once_with()
        fake_service.cleanup.assert_called_once_with()
        mock_handle_plugins_stage.assert_has_calls(stage_calls)
        if reboot:
            self.osutils.reboot.assert_called_once_with()
        else:
            self.assertFalse(self.osutils.reboot.called)

    def _test_configure_host_with_logging(self, extra_logging, reboot=True,
                                          last_stage=False):
        instance_id = 'fake id'
        name = 'fake name'
        version = 'version'
        expected_logging = [
            'Cloudbase-Init version: %s' % version,
            'Metadata service loaded: %r' % name,
            'Instance id: %s' % instance_id,
        ]
        if CONF.metadata_report_provisioning_started:
            expected_logging.insert(2, 'Reporting provisioning started')

        self._test_configure_host(
            expected_logging=expected_logging + extra_logging,
            version=version, name=name, instance_id=instance_id,
            reboot=reboot, last_stage=last_stage)

    @testutils.ConfPatcher('metadata_report_provisioning_completed', True)
    @testutils.ConfPatcher('allow_reboot', False)
    @testutils.ConfPatcher('stop_service_on_exit', False)
    def test_configure_host_no_reboot_no_service_stopping_reporting_done(self):
        self._test_configure_host_with_logging(
            reboot=False,
            extra_logging=['Plugins execution done',
                           'Reporting provisioning completed'],
            last_stage=True)

    @testutils.ConfPatcher('allow_reboot', False)
    @testutils.ConfPatcher('stop_service_on_exit', True)
    def test_configure_host_no_reboot_allow_service_stopping(self):
        self._test_configure_host_with_logging(
            reboot=False,
            extra_logging=['Plugins execution done',
                           'Stopping Cloudbase-Init service'])
        self.osutils.terminate.assert_called_once_with()

    @testutils.ConfPatcher('metadata_report_provisioning_completed', True)
    @testutils.ConfPatcher('allow_reboot', True)
    def test_configure_host_reboot_reporting_started_and_failed(self):
        self._test_configure_host_with_logging(
            extra_logging=['Reporting provisioning failed', 'Rebooting'])

    @testutils.ConfPatcher('check_latest_version', False)
    @mock.patch('cloudbaseinit.version.check_latest_version')
    def test_configure_host(self, mock_check_last_version):
        self._init._check_latest_version()

        self.assertFalse(mock_check_last_version.called)

    @testutils.ConfPatcher('check_latest_version', True)
    @mock.patch('cloudbaseinit.version.check_latest_version')
    def test_configure_host_with_version_check(self, mock_check_last_version):
        self._init._check_latest_version()

        mock_check_last_version.assert_called_once()

    @mock.patch('os.path.basename')
    @mock.patch("sys.executable")
    @mock.patch("sys.argv")
    @mock.patch("sys.exit")
    def _test_reset_service_password_and_respawn(self, mock_exit, mock_argv,
                                                 mock_executable, mock_os_path,
                                                 credentials, current_user):
        token = mock.sentinel.token
        self.osutils.create_user_logon_session.return_value = token
        self.osutils.execute_process_as_user.return_value = 0
        self.osutils.reset_service_password.return_value = credentials
        self.osutils.get_current_user.return_value = current_user
        expected_logging = []
        arguments = sys.argv + ["--noreset_service_password"]

        with testutils.LogSnatcher('cloudbaseinit.init') as snatcher:
            self._init._reset_service_password_and_respawn(self.osutils)

        if not credentials:
            return

        if credentials[1] != current_user[1]:
            expected_logging = [
                "No need to respawn process. Current user: "
                "%(current_user)s. Service user: %(service_user)s" %
                {"current_user": current_user[1],
                 "service_user": credentials[1]}
            ]
            self.assertEqual(expected_logging, snatcher.output)
        else:
            self.osutils.create_user_logon_session.assert_called_once_with(
                credentials[1], credentials[2], credentials[0],
                logon_type=self.osutils.LOGON32_LOGON_BATCH)
            self.osutils.execute_process_as_user.assert_called_once_with(
                token, arguments)
            mock_exit.assert_called_once_with(0)

    def test_reset_service_password_and_respawn(self):
        current_user = [mock.sentinel.domain, mock.sentinel.current_user]
        self._test_reset_service_password_and_respawn(
            credentials=None,
            current_user=current_user
        )
        self._test_reset_service_password_and_respawn(
            credentials=[mock.sentinel.domain, mock.sentinel.user,
                         mock.sentinel.password],
            current_user=current_user
        )
        self._test_reset_service_password_and_respawn(
            credentials=[mock.sentinel.domain, mock.sentinel.current_user,
                         mock.sentinel.password],
            current_user=current_user
        )
