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

import importlib
import os
import unittest
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import encoding

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.metadata.services.azureservice.AzureService"


class AzureServiceTest(unittest.TestCase):

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
        self._azureservice_module = importlib.import_module(
            'cloudbaseinit.metadata.services.azureservice')

        self._azureservice = self._azureservice_module.AzureService()
        self._logsnatcher = testutils.LogSnatcher(
            'cloudbaseinit.metadata.services.azureservice')

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('time.sleep')
    @mock.patch('socket.inet_ntoa')
    @mock.patch('cloudbaseinit.utils.dhcp.get_dhcp_options')
    def _test_get_wire_server_endpoint_address(self, mock_dhcp,
                                               mock_inet_ntoa,
                                               mock_time_sleep,
                                               dhcp_option=None):
        mock_dhcp.return_value = dhcp_option
        if not dhcp_option:
            self.assertRaises(exception.MetadataNotFoundException,
                              (self._azureservice.
                               _get_wire_server_endpoint_address))
        else:
            mock_inet_ntoa.return_value = mock.sentinel.endpoint
            res = self._azureservice._get_wire_server_endpoint_address()
            self.assertEqual(res, mock.sentinel.endpoint)

    def test_get_wire_server_endpoint_address_no_endpoint(self):
        self._test_get_wire_server_endpoint_address()

    def test_get_wire_server_endpoint_address(self):
        dhcp_option = {
            self._azureservice_module.WIRESERVER_DHCP_OPTION:
                'mock.sentinel.endpoint'}
        self._test_get_wire_server_endpoint_address(dhcp_option=dhcp_option)

    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseHTTPMetadataService._http_request')
    def _test_wire_server_request(self,
                                  mock_http_request, mock_base_url=None,
                                  path=None, data_xml=None, headers=None,
                                  parse_xml=True):
        self._azureservice._base_url = mock_base_url
        if not mock_base_url:
            self.assertRaises(exception.CloudbaseInitException,
                              self._azureservice._wire_server_request, path)
            return
        if headers and data_xml:
            expected_headers = self._azureservice._headers.copy()
            expected_headers["Content-Type"] = "text/xml; charset=utf-8"
            expected_headers.update(headers)
            self._azureservice._wire_server_request(path, data_xml, headers,
                                                    parse_xml)
            mock_http_request.assert_called_once_with(path, data_xml,
                                                      headers=expected_headers)
            return
        mock_http_request.return_value = str(mock.sentinel.data)
        res = self._azureservice._wire_server_request(path, data_xml,
                                                      headers, parse_xml)
        self.assertEqual(mock_http_request.call_count, 1)

        if parse_xml:
            self.assertEqual(self._mock_untangle.parse.call_count, 1)
            self.assertEqual(res, self._mock_untangle.parse.return_value)
        else:
            self.assertEqual(res, str(mock.sentinel.data))

    def test_wire_server_request_url_not_set(self):
        self._test_wire_server_request()

    def test_wire_server_request_url_set_no_parse(self):
        mock_base_url = "fake-url"
        self._test_wire_server_request(mock_base_url=mock_base_url,
                                       parse_xml=False)

    def test_wire_server_request_url_set_with_headers(self):
        mock_base_url = "fake-url"
        self._test_wire_server_request(mock_base_url=mock_base_url,
                                       parse_xml=False,
                                       headers={"fake-header": "fake-value"},
                                       data_xml="fake-data")

    def test_wire_server_request_parse_xml(self):
        mock_base_url = "fake-url"
        self._test_wire_server_request(mock_base_url=mock_base_url)

    def test_encode_xml(self):
        fake_root_xml = self._azureservice_module.ElementTree.Element(
            "faketag")
        expected_encoded_xml = ("<?xml version='1.0' encoding='utf-8'?>"
                                "\n<faketag />").encode()
        self.assertEqual(self._azureservice._encode_xml(fake_root_xml),
                         expected_encoded_xml)

    @mock.patch(MODPATH + "._get_role_instance_id")
    @mock.patch(MODPATH + "._get_container_id")
    @mock.patch(MODPATH + "._get_incarnation")
    def test__get_health_report_xml(self, mock_get_incarnation,
                                    mock_get_container_id,
                                    mock_get_role_instance_id):
        mock_state = 'FakeState'
        mock_substatus = 'FakeStatus'
        mock_description = 'FakeDescription'
        mock_get_incarnation.return_value = "fake"
        mock_get_container_id.return_value = "fakeid"
        mock_get_role_instance_id.return_value = "fakeroleid"
        res = self._azureservice._get_health_report_xml(mock_state,
                                                        mock_substatus,
                                                        mock_description)

        expected_result = "<?xml version='1.0' encoding='utf-8'?>\n<Health>" \
            "<GoalStateIncarnation>{}</GoalStateIncarnation>" \
            "<Container><ContainerId>{}</ContainerId>" \
            "<RoleInstanceList><Role><InstanceId>{}</InstanceId>" \
            "<Health><State>{}</State><Details><SubStatus>{}</SubStatus>" \
            "<Description>{}</Description></Details></Health>" \
            "</Role></RoleInstanceList></Container></Health>"
        self.assertEqual(encoding.get_as_string(res),
                         expected_result.format(
                             mock_get_incarnation.return_value,
                             mock_get_container_id.return_value,
                             mock_get_role_instance_id.return_value,
                             mock_state,
                             mock_substatus,
                             mock_description))

    @mock.patch(MODPATH + "._wire_server_request")
    def _test_get_goal_state(self, mock_wire_server_request,
                             goal_state=True, invalid_state=False):
        mock_goalstate = mock.Mock()
        mock_goalstate.GoalState = mock.Mock()
        mock_goalstate.GoalState.Machine = mock.Mock()
        mock_wire_server_request.return_value = mock_goalstate
        if goal_state:
            self._azureservice._goal_state = mock_goalstate
        else:
            self._azureservice._goal_state = False
        if invalid_state:
            mock_goalstate.GoalState.Machine.ExpectedState = \
                not self._azureservice_module.GOAL_STATE_STARTED
            self.assertRaises(exception.CloudbaseInitException,
                              self._azureservice._get_goal_state)
        else:
            if not goal_state:
                mock_goalstate.GoalState.Machine.ExpectedState = \
                    self._azureservice_module.GOAL_STATE_STARTED
            else:
                self._azureservice._goal_state.Machine.ExpectedState = \
                    self._azureservice_module.GOAL_STATE_STARTED
            res = self._azureservice._get_goal_state()
            self.assertEqual(res, mock_goalstate.GoalState)

        if not goal_state:
            mock_wire_server_request.assert_called_once_with(
                "machine?comp=goalstate")

    def test_get_goal_state_exception(self):
        self._test_get_goal_state(invalid_state=True)

    def test_get_goal_state(self):
        self._test_get_goal_state(goal_state=False)

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_incarnation(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Incarnation.cdata = mock.sentinel.cdata

        res = self._azureservice._get_incarnation()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_container_id(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Container.ContainerId.cdata = mock.sentinel.cdata

        res = self._azureservice._get_container_id()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_role_instance_config(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_role = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Container.RoleInstanceList.RoleInstance = mock_role
        mock_role.Configuration = mock.sentinel.config_role

        res = self._azureservice._get_role_instance_config()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.config_role)

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_role_instance_id(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_role = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Container.RoleInstanceList.RoleInstance = mock_role
        mock_role.InstanceId.cdata = mock.sentinel.config_role

        res = self._azureservice._get_role_instance_id()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.config_role)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_health_report_xml")
    def test__post_health_status(self, mock_get_health_report_xml,
                                 mock_wire_server_request):
        mock_get_health_report_xml.return_value = mock.sentinel.report_xml
        mock_state = mock.sentinel.state
        expected_logging = ["Health data: %s" % mock.sentinel.report_xml]
        with self._logsnatcher:
            self._azureservice._post_health_status(state=mock_state)
        self.assertEqual(self._logsnatcher.output, expected_logging)
        mock_get_health_report_xml.assert_called_once_with(mock_state,
                                                           None, None)
        mock_wire_server_request.assert_called_once_with(
            "machine?comp=health", mock.sentinel.report_xml, parse_xml=False)

    @mock.patch(MODPATH + "._post_health_status")
    def test_provisioning_started(self, mock_post_health_status):
        self._azureservice.provisioning_started()
        mock_post_health_status.assert_called_once_with(
            self._azureservice_module.HEALTH_STATE_NOT_READY,
            self._azureservice_module.HEALTH_SUBSTATE_PROVISIONING,
            "Cloudbase-Init is preparing your computer for first use...")

    @mock.patch(MODPATH + "._post_health_status")
    def test_provisioning_completed(self, mock_post_health_status):
        self._azureservice.provisioning_completed()
        mock_post_health_status.assert_called_once_with(
            self._azureservice_module.HEALTH_STATE_READY)

    @mock.patch(MODPATH + "._post_health_status")
    def test_provisioning_failed(self, mock_post_health_status):
        self._azureservice.provisioning_failed()
        mock_post_health_status.assert_called_once_with(
            self._azureservice_module.HEALTH_STATE_NOT_READY,
            self._azureservice_module.HEALTH_SUBSTATE_PROVISIONING_FAILED,
            "Provisioning failed")

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_properties_xml")
    def test__post_role_properties(self, mock_get_role_properties_xml,
                                   mock_wire_server_request):
        mock_properties = mock.sentinel.properties
        mock_get_role_properties_xml.return_value = mock_properties
        expected_logging = ["Role properties data: %s" % mock_properties]
        with self._logsnatcher:
            self._azureservice._post_role_properties(mock_properties)
        self.assertEqual(self._logsnatcher.output, expected_logging)
        mock_get_role_properties_xml.assert_called_once_with(mock_properties)
        mock_wire_server_request.assert_called_once_with(
            "machine?comp=roleProperties", mock_properties, parse_xml=False)

    def test_can_post_rdp_cert_thumbprint(self):
        self.assertTrue(self._azureservice.can_post_rdp_cert_thumbprint)

    @mock.patch(MODPATH + "._post_role_properties")
    def test_post_rdp_cert_thumbprint(self, mock_post_role_properties):
        mock_thumbprint = mock.sentinel.thumbprint
        self._azureservice.post_rdp_cert_thumbprint(mock_thumbprint)
        expected_props = {
            self._azureservice_module.ROLE_PROPERTY_CERT_THUMB:
                mock_thumbprint}
        mock_post_role_properties.assert_called_once_with(expected_props)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_hosting_environment(self, mock_get_role_instance_config,
                                      mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.HostingEnvironmentConfig.cdata = mock.sentinel.data

        self._azureservice._get_hosting_environment()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_shared_config(self, mock_get_role_instance_config,
                                mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.SharedConfig.cdata = mock.sentinel.data

        self._azureservice._get_shared_config()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_extensions_config(self, mock_get_role_instance_config,
                                    mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.ExtensionsConfig.cdata = mock.sentinel.data

        self._azureservice._get_extensions_config()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_full_config(self, mock_get_role_instance_config,
                              mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.FullConfig.cdata = mock.sentinel.data

        self._azureservice._get_full_config()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    def test__create_transport_cert(self):
        mock_cert_mgr = mock.Mock()
        expected_certs = (mock.sentinel.thumbprint, mock.sentinel.cert)

        mock_cert_mgr.create_self_signed_cert.return_value = (
            mock.sentinel.thumbprint, mock.sentinel.cert)
        with testutils.ConfPatcher(key='transport_cert_store_name',
                                   value='fake_name', group="azure"):
            with self._azureservice._create_transport_cert(mock_cert_mgr) as r:
                self.assertEqual(r, expected_certs)
        (mock_cert_mgr.create_self_signed_cert.
            assert_called_once_with("CN=Cloudbase-Init AzureService Transport",
                                    machine_keyset=True,
                                    store_name="fake_name"))
        (mock_cert_mgr.delete_certificate_from_store.
            assert_called_once_with(mock.sentinel.thumbprint,
                                    machine_keyset=True,
                                    store_name="fake_name"))

    @mock.patch(MODPATH + "._wire_server_request")
    def test__get_encoded_cert(self, mock_wire_server_request):
        mock_cert_config = mock.Mock()
        mock_transport_cert = mock.Mock()
        mock_cert_url = mock.sentinel.cert_url

        mock_transport_cert.replace.return_value = mock.sentinel.transport_cert
        mock_wire_server_request.return_value = mock_cert_config
        mock_cert_config.CertificateFile.Data.cdata = mock.sentinel.cert_data
        mock_cert_config.CertificateFile.Format.cdata = mock.sentinel.cert_fmt

        expected_headers = {
            "x-ms-guest-agent-public-x509-cert": mock.sentinel.transport_cert}
        expected_result = (mock.sentinel.cert_data, mock.sentinel.cert_fmt)
        res = self._azureservice._get_encoded_cert(mock_cert_url,
                                                   mock_transport_cert)
        (mock_wire_server_request.
            assert_called_once_with(mock_cert_url, headers=expected_headers))
        self.assertEqual(res, expected_result)

    @mock.patch(MODPATH + "._get_versions")
    def _test__check_version_header(self, mock_get_versions, version):
        mock_version = mock.Mock()
        mock_get_versions.return_value = mock_version
        mock_version.Versions.Supported.Version = [version]
        if self._azureservice_module.WIRE_SERVER_VERSION is not version:
            self.assertRaises(exception.MetadataNotFoundException,
                              self._azureservice._check_version_header)
        else:
            self._azureservice._check_version_header()
            self.assertEqual(self._azureservice._headers["x-ms-version"],
                             version)

    def test_check_version_header_unsupported_version(self):
        version = "fake-version"
        self._test__check_version_header(version=version)

    def test_check_version_header_supported(self):
        version = self._azureservice_module.WIRE_SERVER_VERSION
        self._test__check_version_header(version=version)

    @mock.patch(MODPATH + "._wire_server_request")
    def test__get_versions(self, mock_server_request):
        mock_server_request.return_value = mock.sentinel.version
        res = self._azureservice._get_versions()
        mock_server_request.assert_called_once_with("?comp=Versions")
        self.assertEqual(res, mock.sentinel.version)

    @mock.patch(MODPATH + "._get_role_instance_id")
    def test_get_instance_id(self, mock_get_role_instance_id):
        mock_get_role_instance_id.return_value = mock.sentinel.id
        self.assertEqual(self._azureservice.get_instance_id(),
                         mock.sentinel.id)

    @mock.patch("os.path.exists")
    @mock.patch(MODPATH + "._get_config_set_drive_path")
    def _test__get_ovf_env_path(self, mock_get_drives, mock_path_exists,
                                path_exists=True):
        mock_get_drives.return_value = 'fake path'
        mock_path_exists.return_value = path_exists
        self._azureservice._osutils.get_logical_drives = mock_get_drives
        if not path_exists:
            self.assertRaises(exception.ItemNotFoundException,
                              self._azureservice._get_ovf_env_path)
        else:
            res = self._azureservice._get_ovf_env_path()
            ovf_env_path = os.path.join(
                "fake path", self._azureservice_module.OVF_ENV_FILENAME)
            self.assertEqual(res, ovf_env_path)
            mock_path_exists.assert_called_once_with(ovf_env_path)
        mock_get_drives.assert_called_once_with()

    def test_get_ovf_env_path_exists(self):
        self._test__get_ovf_env_path()

    def test_get_ovf_env_path_not_exists(self):
        self._test__get_ovf_env_path(path_exists=False)

    @mock.patch(MODPATH + "._get_ovf_env_path")
    def test_get_ovf_env(self, mock_get_ovf_env_path):
        fake_xml = '<?xml version="1.0"?><root><child name="fake"/></root>'
        mock_get_ovf_env_path.return_value = fake_xml
        res = self._azureservice._get_ovf_env()
        self.assertIsNotNone(res)
        mock_get_ovf_env_path.assert_called_once_with()

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_admin_username(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.AdminUsername.cdata = mock.sentinel.cdata
        res = self._azureservice.get_admin_username()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_admin_password(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.AdminPassword.cdata = mock.sentinel.cdata
        res = self._azureservice.get_admin_password()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_host_name(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.ComputerName.cdata = mock.sentinel.cdata
        res = self._azureservice.get_host_name()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_enable_automatic_updates(self, mock_get_ovf_env,
                                          enable_updates=True):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        if not enable_updates:
            mock_win_prov = mock.MagicMock(spec="")
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        res = self._azureservice.get_enable_automatic_updates()
        mock_get_ovf_env.assert_called_once_with()
        self.assertFalse(res)

    def test_get_enable_automatic_updates_no_updates(self):
        self.test_get_enable_automatic_updates(enable_updates=False)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_winrm_listeners_configuration(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_listener = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.WinRM.Listeners.Listener = [mock_listener]
        mock_listener.Protocol.cdata = mock.sentinel.fake_protocol
        (mock_listener.CertificateThumbprint.
            cdata) = mock.sentinel.fake_thumbprint

        expected_result = [
            {
                'certificate_thumbprint': mock.sentinel.fake_thumbprint,
                'protocol': mock.sentinel.fake_protocol,
            }]
        res = self._azureservice.get_winrm_listeners_configuration()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, expected_result)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_vm_agent_package_provisioning_data(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_package_name = mock.sentinel.package_name
        mock_get_ovf_env.return_value = mock_ovf_env
        (mock_ovf_env.Environment.wa_PlatformSettingsSection.
            PlatformSettings.GuestAgentPackageName.cdata) = mock_package_name
        res = self._azureservice.get_vm_agent_package_provisioning_data()
        expected_provisioning_data = {
            'provision': False, 'package_name': mock_package_name}
        self.assertEqual(res, expected_provisioning_data)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_kms_host(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        self.assertTrue(self._azureservice.get_kms_host())

    @mock.patch(MODPATH + "._get_ovf_env")
    def _test_get_use_avma_licensing(self, mock_get_ovf_env, use_avma):
        mock_ovf_env = mock.Mock()
        mock_ovf_env.Environment = mock.Mock()
        plat_sett_section = mock.Mock()
        if not use_avma:
            plat_sett_section.PlatformSettings = mock.MagicMock(spec="")
        mock_ovf_env.Environment.wa_PlatformSettingsSection = plat_sett_section
        mock_get_ovf_env.return_value = mock_ovf_env

        self.assertFalse(self._azureservice.get_use_avma_licensing())
        mock_get_ovf_env.assert_called_once_with()

    def test_get_use_avma_licensing(self):
        self._test_get_use_avma_licensing(use_avma=True)

    def test_get_use_avma_licensing_no_use_avma(self):
        self._test_get_use_avma_licensing(use_avma=False)

    @mock.patch(MODPATH + "._get_ovf_env")
    @mock.patch(MODPATH + "._check_version_header")
    @mock.patch(MODPATH + "._get_wire_server_endpoint_address")
    def _test_load(self, mock_get_endpoint_address,
                   mock_check_version_header, mock_get_ovf_env,
                   endpoint_side_effect=None, load_side_effect=None):
        if endpoint_side_effect:
            mock_get_endpoint_address.side_effect = endpoint_side_effect
            mock_endpoint = "168.63.129.16"
            expected_logging = [
                "Azure WireServer endpoint not found. "
                "Using default endpoint 168.63.129.16."]
            with self._logsnatcher:
                res = self._azureservice.load()
                self.assertTrue(res)
            self.assertEqual(self._logsnatcher.output, expected_logging)
            mock_get_endpoint_address.assert_called_once_with()
        else:
            mock_endpoint = mock.sentinel.endpoint
            mock_get_endpoint_address.return_value = mock_endpoint

        if load_side_effect:
            mock_check_version_header.side_effect = load_side_effect
            res = self._azureservice.load()
            self.assertFalse(res)
            return
        else:
            res = self._azureservice.load()
            self.assertTrue(res)
            self.assertIn(str(mock_endpoint), self._azureservice._base_url)
            mock_check_version_header.assert_called_with()
            mock_get_ovf_env.assert_called_with()

    def test_load_no_endpoint(self):
        self._test_load(endpoint_side_effect=Exception)

    def test_load_exception(self):
        exc = Exception("Fake exception")
        self._test_load(load_side_effect=exc)

    def test_load(self):
        self._test_load()

    @mock.patch('os.path.exists')
    def _test_get_config_set_drive_path(self, mock_path_exists,
                                        path_exists=True):
        self._azureservice._set_config_drive_path = None
        mock_osutils = mock.Mock()
        mock_osutils.get_logical_drives.return_value = ['fake path'] * 3
        self._azureservice._osutils = mock_osutils
        mock_path_exists.side_effect = [False] * 2 + [path_exists]
        if path_exists:
            result = self._azureservice._get_config_set_drive_path()
            self.assertEqual(result, 'fake path')
        else:
            self.assertRaises(exception.ItemNotFoundException,
                              self._azureservice._get_config_set_drive_path)
        self.assertEqual(mock_path_exists.call_count, 3)

    def test_get_config_set_drive_path(self):
        self._test_get_config_set_drive_path()

    def test_get_config_set_drive_path_not_exists(self):
        self._test_get_config_set_drive_path(path_exists=False)

    @mock.patch(MODPATH + '._get_ovf_env')
    def test_check_ovf_env_custom_data(self, mock_get_ovf_env,
                                       custom_data=True):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_win_prov.PlatformSettings = mock.Mock()
        if not custom_data:
            mock_win_prov.PlatformSettings = mock.MagicMock(spec="")
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        res = self._azureservice._check_ovf_env_custom_data()
        mock_get_ovf_env.assert_called_once_with()
        self.assertTrue(res)

    @mock.patch(MODPATH + '._check_ovf_env_custom_data')
    def test_get_user_data_ItemNotFound(self, mock_check_custom_data):
        mock_check_custom_data.return_value = True
        self._azureservice._config_set_drive_path = "fake path"
        self.assertRaises(exception.ItemNotFoundException,
                          self._azureservice.get_user_data)

    @mock.patch(MODPATH + '._check_ovf_env_custom_data')
    def test_get_user_data_NoMetadataException(self, mock_check_custom_data):
        mock_check_custom_data.return_value = False
        self._azureservice._config_set_drive_path = "fake path"
        self.assertRaises(
            self._azureservice_module.base.NotExistingMetadataException,
            self._azureservice.get_user_data)

    @mock.patch(MODPATH + '._get_role_instance_config')
    def test_get_server_certs_no_certs(self, mock_get_instance_config):
        mock_get_instance_config.return_value = mock.MagicMock(spec="")
        res = self._azureservice.get_server_certs()
        self.assertEqual(res, [])

    @mock.patch(MODPATH + '._get_hosting_environment')
    @mock.patch(MODPATH + '._get_encoded_cert')
    @mock.patch(MODPATH + '._get_role_instance_config')
    @mock.patch(MODPATH + '._create_transport_cert')
    @mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager')
    def test_get_server_certs(self, mock_cert_manager, mock_create_cert,
                              mock_get_config, mock_get_encoded_cert,
                              mock_get_hosting_env):
        cert_model = {
            "storeName": mock.sentinel.storeName,
            "configurationLevel": mock.sentinel.configurationLevel,
            "certificateId": mock.sentinel.certificateId,
            "name": mock.sentinel.name
        }
        mock_cert_mgr = mock.Mock()
        mock_cert_mgr.decode_pkcs7_base64_blob.return_value = \
            mock.sentinel.pfx_data
        mock_cert_manager.return_value = mock_cert_mgr
        mock_create_cert.return_value.__enter__.return_value = \
            (mock.sentinel.thumbprint, mock.sentinel.cert)
        mock_get_encoded_cert.return_value = \
            (mock.sentinel.cert_data, mock.sentinel.cert_format)
        mock_host_env = mock.Mock()
        mock_host_env_config = mock_host_env.HostingEnvironmentConfig
        mock_host_env_config.StoredCertificates.StoredCertificate = \
            [cert_model]
        mock_get_hosting_env.return_value = mock_host_env

        res = self._azureservice.get_server_certs()
        expected_result = [{
            "store_name": mock.sentinel.storeName,
            "store_location": mock.sentinel.configurationLevel,
            "certificate_id": mock.sentinel.certificateId,
            "name": mock.sentinel.name,
            "pfx_data": mock.sentinel.pfx_data,
        }]
        self.assertEqual(res, expected_result)
        self.assertEqual(mock_create_cert.call_count, 1)
        self.assertEqual(mock_get_encoded_cert.call_count, 1)
        self.assertEqual(mock_cert_mgr.decode_pkcs7_base64_blob.call_count, 1)
        mock_cert_manager.assert_called_once_with()
        mock_get_config.assert_called_once_with()
        mock_get_hosting_env.assert_called_once_with()

    @mock.patch(MODPATH + '.get_user_data')
    def test_get_decoded_user_data(self, mock_get_user_data):
        mock_get_user_data.return_value = mock.sentinel.user_data
        res = self._azureservice.get_decoded_user_data()
        self.assertEqual(res, mock.sentinel.user_data)

    @mock.patch(MODPATH + '.get_content')
    def test_get_ephemeral_disk_data_loss_warning(self, mock_get_content):
        mock_get_content.return_value = mock.sentinel.content
        res = self._azureservice.get_ephemeral_disk_data_loss_warning()
        self.assertEqual(res, mock.sentinel.content)
        mock_get_content.assert_called_once_with(
            self._azureservice_module.DATALOSS_WARNING_PATH)

    @mock.patch(MODPATH + "._get_role_instance_id")
    @mock.patch(MODPATH + "._get_container_id")
    def _test_get_role_properties_xml(self, mock_get_container_id,
                                      mock_get_role_instance_id,
                                      properties):
        mock_get_container_id.return_value = "fake container id"
        mock_get_role_instance_id.return_value = "fake instance id"

        res = self._azureservice._get_role_properties_xml(properties)
        expected_properties = ""
        property_template = '<Property name=\"{property_name}"'\
                            ' value="{value}" />'
        result_template = ("<?xml version=\'1.0\' encoding=\'utf-8\'?>\n"
                           "<RoleProperties><Container><ContainerId>"
                           "{container_id}</ContainerId><RoleInstances>"
                           "<RoleInstance><Id>{instance_id}</Id>"
                           "{properties}</RoleInstance>"
                           "</RoleInstances></Container></RoleProperties>")
        if properties:
            expected_properties = "<Properties>"
            for name, value in properties.items():
                expected_properties += property_template.format(
                    property_name=name,
                    value=value)
            expected_properties += "</Properties>"
        else:
            expected_properties = "<Properties />"
        expected_result = result_template.format(
            container_id=mock_get_container_id.return_value,
            instance_id=mock_get_role_instance_id.return_value,
            properties=expected_properties)
        self.assertEqual(encoding.get_as_string(res), expected_result)

    def test_get_role_properties_xml_no_properties(self):
        self._test_get_role_properties_xml(properties={})

    def test_get_role_properties_xml(self):
        properties = {
            "fake property 1": "fake value 1",
            "fake property 2": "fake value 2"
        }
        self._test_get_role_properties_xml(properties=properties)
