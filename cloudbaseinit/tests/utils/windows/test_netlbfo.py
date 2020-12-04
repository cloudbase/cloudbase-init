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

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.models import network as network_model

MODPATH = "cloudbaseinit.utils.windows.netlbfo"


class NetLBFOTest(unittest.TestCase):

    def setUp(self):
        self._wmi_mock = mock.MagicMock()
        self._mi_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules', {
                'wmi': self._wmi_mock,
                'mi': self._mi_mock})
        self._module_patcher.start()
        self._netlbfo = importlib.import_module(MODPATH)

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('time.sleep')
    @mock.patch(MODPATH + '.NetLBFOTeamManager._get_primary_adapter_name')
    @mock.patch(MODPATH + '.NetLBFOTeamManager._create_team')
    @mock.patch(MODPATH + '.NetLBFOTeamManager._add_team_member')
    @mock.patch(MODPATH + '.NetLBFOTeamManager._set_primary_nic_vlan_id')
    @mock.patch(MODPATH + '.NetLBFOTeamManager._wait_for_nic')
    @mock.patch(MODPATH + '.NetLBFOTeamManager.delete_team')
    def _test_create_team(self, mock_delete_team, mock_wait_for_nic,
                          mock_set_primary_nic_vlan_id, mock_add_team_member,
                          mock_create_team, mock_primary_adapter_name,
                          mock_time_sleep, mode_not_found=False,
                          lb_algo_not_found=False,
                          add_team_member_fail=False):
        mock_primary_adapter_name.return_value = mock.sentinel.pri_nic_name
        mock_create_team.return_value = None

        lacp_timer = network_model.BOND_LACP_RATE_FAST
        members = [mock.sentinel.pri_nic_name, mock.sentinel.other_member]

        conn = self._wmi_mock.WMI.return_value
        mock_team = mock.Mock()
        conn.MSFT_NetLbfoTeam.new.return_value = mock_team
        mock_team_nic = mock.Mock()
        mock_team_nic.Name = mock.Mock()
        conn.MSFT_NetLbfoTeamNic.return_value = [mock_team_nic]

        if mode_not_found:
            mode = "fake mode"
        else:
            mode = network_model.BOND_TYPE_8023AD

        if lb_algo_not_found:
            lb_algo = "fake lb algo"
        else:
            lb_algo = network_model.BOND_LB_ALGO_L2

        if add_team_member_fail:
            ex = exception.CloudbaseInitException
            mock_add_team_member.side_effect = ex

        if mode_not_found or lb_algo_not_found:
            self.assertRaises(
                exception.ItemNotFoundException,
                self._netlbfo.NetLBFOTeamManager().create_team,
                mock.sentinel.team_name, mode, lb_algo, members,
                mock.sentinel.mac, mock.sentinel.pri_nic_name,
                mock.sentinel.vlan_id, lacp_timer)
            return
        elif add_team_member_fail:
            self.assertRaises(
                exception.CloudbaseInitException,
                self._netlbfo.NetLBFOTeamManager().create_team,
                mock.sentinel.team_name, mode, lb_algo, members,
                mock.sentinel.mac, mock.sentinel.pri_nic_name,
                mock.sentinel.vlan_id, lacp_timer)
        else:
            self._netlbfo.NetLBFOTeamManager().create_team(
                mock.sentinel.team_name, mode, lb_algo, members,
                mock.sentinel.mac, mock.sentinel.pri_nic_name,
                mock.sentinel.vlan_id, lacp_timer)

        if not add_team_member_fail:
            mock_set_primary_nic_vlan_id.assert_called_once_with(
                conn, mock.sentinel.team_name, mock.sentinel.vlan_id)
            mock_create_team.assert_called_once_with(
                conn, mock.sentinel.team_name, mock.sentinel.pri_nic_name,
                2, 3, mock.sentinel.pri_nic_name, 1)
            mock_wait_for_nic.assert_called_once_with(
                mock_team_nic.Name)
            mock_add_team_member.assert_called_once_with(
                conn, mock.sentinel.team_name, mock.sentinel.other_member)
        else:
            mock_add_team_member.assert_called_with(
                conn, mock.sentinel.team_name, mock.sentinel.other_member)
            mock_delete_team.assert_called_with(mock.sentinel.team_name)
            self.assertEqual(mock_add_team_member.call_count, 6)
            self.assertEqual(mock_delete_team.call_count, 6)

    def test_create_team(self):
        self._test_create_team()

    def test_create_team_mode_not_found(self):
        self._test_create_team(mode_not_found=True)

    def test_create_team_mode_lb_algo_not_found(self):
        self._test_create_team(lb_algo_not_found=True)

    def test_create_team_add_team_member_fail(self):
        self._test_create_team(add_team_member_fail=True)

    def test_delete_team(self):
        conn = self._wmi_mock.WMI.return_value
        mock_team = mock.Mock()
        conn.MSFT_NetLbfoTeam.return_value = [mock_team]

        self._netlbfo.NetLBFOTeamManager().delete_team(mock.sentinel.team_name)

        conn.MSFT_NetLbfoTeam.assert_called_once_with(
            name=mock.sentinel.team_name)
        mock_team.Delete_.assert_called_once_with()

    def test_create_team_private(self):
        conn = self._wmi_mock.WMI.return_value
        mock_team = mock.Mock()
        conn.MSFT_NetLbfoTeam.new.return_value = mock_team
        teaming_mode = 1
        lb_algo = 2
        lacp_timer = 1

        custom_options = [
            {
                u'name': u'TeamMembers',
                u'value_type':
                    self._mi_mock.MI_ARRAY | self._mi_mock.MI_STRING,
                u'value': [mock.sentinel.private_nic_team]
            },
            {
                u'name': u'TeamNicName',
                u'value_type': self._mi_mock.MI_STRING,
                u'value': mock.sentinel.team_nic_name
            }
        ]

        operation_options = {u'custom_options': custom_options}
        self._netlbfo.NetLBFOTeamManager()._create_team(
            conn, mock.sentinel.team_name, mock.sentinel.team_nic_name,
            teaming_mode, lb_algo, mock.sentinel.private_nic_team,
            lacp_timer)

        self.assertEqual(mock.sentinel.team_name, mock_team.Name)
        self.assertEqual(teaming_mode, mock_team.TeamingMode)
        self.assertEqual(lb_algo, mock_team.LoadBalancingAlgorithm)
        self.assertEqual(lacp_timer, mock_team.LacpTimer)
        mock_team.put.assert_called_once_with(
            operation_options=operation_options)

    @mock.patch(MODPATH + '.NetLBFOTeamManager._wait_for_nic')
    def test_add_team_nic(self, mock_wait_for_nic):
        conn = self._wmi_mock.WMI.return_value
        mock_team_nic = mock.Mock()
        conn.MSFT_NetLbfoTeamNIC.new.return_value = mock_team_nic

        self._netlbfo.NetLBFOTeamManager().add_team_nic(
            mock.sentinel.team_name, mock.sentinel.nic_name,
            mock.sentinel.vlan_id)

        self.assertEqual(mock.sentinel.team_name, mock_team_nic.Team)
        self.assertEqual(mock.sentinel.nic_name, mock_team_nic.Name)
        self.assertEqual(mock.sentinel.vlan_id, mock_team_nic.VlanID)
        mock_team_nic.put.assert_called_once_with()
        mock_wait_for_nic.assert_called_once_with(mock_team_nic.Name)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_is_available(self, mock_get_os_utils):
        os_utils = mock_get_os_utils.return_value
        os_utils.check_os_version.return_value = True
        os_utils.is_client_os.return_value = False
        with mock.patch('sys.platform', 'win32'):
            self.assertEqual(
                True, self._netlbfo.NetLBFOTeamManager.is_available())

    @mock.patch('time.sleep')
    def test_wait_for_nic(self, mock_sleep):
        conn = self._wmi_mock.WMI.return_value
        conn.Win32_NetworkAdapter.side_effect = [
            [], [mock.sentinel.net_adapter]]

        self._netlbfo.NetLBFOTeamManager()._wait_for_nic(
            mock.sentinel.nic_name)

        conn.Win32_NetworkAdapter.assert_has_calls([
            mock.call(NetConnectionID=mock.sentinel.nic_name),
            mock.call(NetConnectionID=mock.sentinel.nic_name)])
        mock_sleep.assert_called_once_with(1)

    def test_set_primary_nic_vlan_id(self):
        conn = mock.Mock()
        mock_team_nic = mock.Mock()
        conn.MSFT_NetLbfoTeamNIC.return_value = [mock_team_nic]

        self._netlbfo.NetLBFOTeamManager()._set_primary_nic_vlan_id(
            conn, mock.sentinel.team_name, mock.sentinel.vlan_id)

        custom_options = [{
            u'name': u'VlanID',
            u'value_type': self._mi_mock.MI_UINT32,
            u'value': mock.sentinel.vlan_id
        }]
        operation_options = {u'custom_options': custom_options}
        mock_team_nic.put.assert_called_once_with(
            operation_options=operation_options)

    def test_add_team_member(self):
        conn = mock.Mock()
        mock_team_member = mock.Mock()
        conn.MSFT_NetLbfoTeamMember.new.return_value = mock_team_member

        self._netlbfo.NetLBFOTeamManager()._add_team_member(
            conn, mock.sentinel.team_name, mock.sentinel.team_member)

        custom_options = [{
            u'name': u'Name',
            u'value_type': self._mi_mock.MI_STRING,
            u'value': mock.sentinel.team_member
        }]
        operation_options = {u'custom_options': custom_options}
        mock_team_member.put.assert_called_once_with(
            operation_options=operation_options)
        self.assertEqual(mock.sentinel.team_name, mock_team_member.Team)

    def _test_get_primary_adapter_name(self, mac_not_found=False,
                                       member_not_found=False):
        mock_members = [mock.sentinel.team_member]
        conn = self._wmi_mock.WMI.return_value

        if mac_not_found:
            conn.Win32_NetworkAdapter.return_value = []
        else:
            conn.Win32_NetworkAdapter.return_value = [
                mock.sentinel.net_adapter]

        if member_not_found:
            net_conn_id = mock.sentinel.something_else
        else:
            net_conn_id = mock.sentinel.team_member
        mock.sentinel.net_adapter.NetConnectionID = net_conn_id

        if mac_not_found or member_not_found:
            self.assertRaises(
                exception.ItemNotFoundException,
                self._netlbfo.NetLBFOTeamManager()._get_primary_adapter_name,
                mock_members, mock.sentinel.mac)
        else:
            self.assertEqual(
                mock.sentinel.team_member,
                self._netlbfo.NetLBFOTeamManager()._get_primary_adapter_name(
                    mock_members, mock.sentinel.mac))

        conn.Win32_NetworkAdapter.assert_called_once_with(
            MACAddress=mock.sentinel.mac)

    def test_get_primary_adapter_name(self):
        self._test_get_primary_adapter_name()

    def test_get_primary_adapter_name_mac_not_found(self):
        self._test_get_primary_adapter_name(mac_not_found=True)

    def test_get_primary_adapter_name_member_not_found(self):
        self._test_get_primary_adapter_name(member_not_found=True)
