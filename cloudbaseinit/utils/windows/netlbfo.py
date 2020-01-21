# Copyright 2018 Cloudbase Solutions Srl
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

import mi
from oslo_log import log as oslo_logging
import wmi

from cloudbaseinit import exception
from cloudbaseinit.models import network as network_model
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import network_team
from cloudbaseinit.utils import retry_decorator

LBFO_TEAM_MODE_STATIC = 0
LBFO_TEAM_MODE_SWITCH_INDEPENDENT = 1
LBFO_TEAM_MODE_LACP = 2

LBFO_TEAM_ALGORITHM_TRANSPORT_PORTS = 0
LBFO_TEAM_ALGORITHM_IP_ADDRESSES = 2
LBFO_TEAM_ALGORITHM_MAC_ADDRESSES = 3
LBFO_TEAM_ALGORITHM_HYPERV_PORT = 4
LBFO_TEAM_ALGORITHM_DYNAMIC = 5

LBFO_TEST_LACP_TIMER_SLOW = 0
LBFO_TEST_LACP_TIMER_FAST = 1

NETWORK_MODEL_TEAM_MODE_MAP = {
    network_model.BOND_TYPE_8023AD: LBFO_TEAM_MODE_LACP,
    network_model.BOND_TYPE_BALANCE_RR: LBFO_TEAM_MODE_STATIC,
    network_model.BOND_TYPE_ACTIVE_BACKUP: LBFO_TEAM_MODE_SWITCH_INDEPENDENT,
    network_model.BOND_TYPE_BALANCE_XOR: LBFO_TEAM_MODE_STATIC,
    network_model.BOND_TYPE_BALANCE_TLB: LBFO_TEAM_MODE_SWITCH_INDEPENDENT,
    network_model.BOND_TYPE_BALANCE_ALB: LBFO_TEAM_MODE_SWITCH_INDEPENDENT,
}

NETWORK_MODEL_LB_ALGO_MAP = {
    network_model.BOND_LB_ALGO_L2: LBFO_TEAM_ALGORITHM_MAC_ADDRESSES,
    network_model.BOND_LB_ALGO_L2_L3: LBFO_TEAM_ALGORITHM_IP_ADDRESSES,
    network_model.BOND_LB_ALGO_L3_L4: LBFO_TEAM_ALGORITHM_TRANSPORT_PORTS,
    network_model.BOND_LB_ENCAP_L2_L3: LBFO_TEAM_ALGORITHM_IP_ADDRESSES,
    network_model.BOND_LB_ENCAP_L3_L4: LBFO_TEAM_ALGORITHM_TRANSPORT_PORTS,
}

NETWORK_MODEL_LACP_RATE_MAP = {
    network_model.BOND_LACP_RATE_FAST: LBFO_TEST_LACP_TIMER_FAST,
    network_model.BOND_LACP_RATE_SLOW: LBFO_TEST_LACP_TIMER_SLOW,
}

LOG = oslo_logging.getLogger(__name__)


class NetLBFOTeamManager(network_team.BaseNetworkTeamManager):
    @staticmethod
    def _get_primary_adapter_name(members, mac_address):
        conn = wmi.WMI(moniker='root/cimv2')
        adapters = conn.Win32_NetworkAdapter(MACAddress=mac_address)
        if not adapters:
            raise exception.ItemNotFoundException(
                "No adapter with MAC address \"%s\" found" % mac_address)
        primary_adapter_name = adapters[0].NetConnectionID

        if primary_adapter_name not in members:
            raise exception.ItemNotFoundException(
                "Adapter \"%s\" not found in members" % primary_adapter_name)
        return primary_adapter_name

    @staticmethod
    @retry_decorator.retry_decorator(max_retry_count=3)
    def _add_team_member(conn, team_name, member):
        team_member = conn.MSFT_NetLbfoTeamMember.new()
        team_member.Team = team_name
        custom_options = [{
            u'name': u'Name',
            u'value_type': mi.MI_STRING,
            u'value': member
        }]
        operation_options = {u'custom_options': custom_options}
        team_member.put(operation_options=operation_options)

    @staticmethod
    @retry_decorator.retry_decorator(max_retry_count=3)
    def _set_primary_nic_vlan_id(conn, team_name, vlan_id):
        team_nic = conn.MSFT_NetLbfoTeamNIC(Team=team_name, Primary=True)[0]

        custom_options = [{
            u'name': u'VlanID',
            u'value_type': mi.MI_UINT32,
            u'value': vlan_id
        }]

        operation_options = {u'custom_options': custom_options}
        team_nic.put(operation_options=operation_options)

    @staticmethod
    @retry_decorator.retry_decorator(max_retry_count=3)
    def _create_team(conn, team_name, nic_name, teaming_mode, lb_algo,
                     primary_adapter_name, lacp_timer=None):

        team = conn.MSFT_NetLbfoTeam.new()
        team.Name = team_name
        team.TeamingMode = teaming_mode
        team.LoadBalancingAlgorithm = lb_algo
        if lacp_timer:
            team.LacpTimer = lacp_timer

        custom_options = [
            {
                u'name': u'TeamMembers',
                u'value_type': mi.MI_ARRAY | mi.MI_STRING,
                u'value': [primary_adapter_name]
            },
            {
                u'name': u'TeamNicName',
                u'value_type': mi.MI_STRING,
                u'value': nic_name
            }
        ]

        operation_options = {u'custom_options': custom_options}
        team.put(operation_options=operation_options)

    @retry_decorator.retry_decorator(max_retry_count=5)
    def create_team(self, team_name, mode, load_balancing_algorithm,
                    members, mac_address, primary_nic_name=None,
                    primary_nic_vlan_id=None, lacp_timer=None):
        conn = wmi.WMI(moniker='root/standardcimv2')

        primary_adapter_name = self._get_primary_adapter_name(
            members, mac_address)

        teaming_mode = NETWORK_MODEL_TEAM_MODE_MAP.get(mode)
        if teaming_mode is None:
            raise exception.ItemNotFoundException(
                "Unsupported teaming mode: %s" % mode)

        if load_balancing_algorithm is None:
            lb_algo = LBFO_TEAM_ALGORITHM_DYNAMIC
        else:
            lb_algo = NETWORK_MODEL_LB_ALGO_MAP.get(
                load_balancing_algorithm)
            if lb_algo is None:
                raise exception.ItemNotFoundException(
                    "Unsupported LB algorithm: %s" % load_balancing_algorithm)

        if lacp_timer is not None and teaming_mode == LBFO_TEAM_MODE_LACP:
            lacp_timer = NETWORK_MODEL_LACP_RATE_MAP[lacp_timer]

        nic_name = primary_nic_name or team_name

        self._create_team(conn, team_name, nic_name, teaming_mode, lb_algo,
                          primary_adapter_name, lacp_timer)

        try:
            for member in members:
                if member != primary_adapter_name:
                    self._add_team_member(conn, team_name, member)

            if primary_nic_vlan_id is not None:
                self._set_primary_nic_vlan_id(
                    conn, team_name, primary_nic_vlan_id)

            nic_name = conn.MSFT_NetLbfoTeamNic(team=team_name)[0].Name
            self._wait_for_nic(nic_name)
        except Exception as ex:
            self.delete_team(team_name)
            raise ex

    @staticmethod
    @retry_decorator.retry_decorator(max_retry_count=10,
                                     max_sleep_time=10)
    def _wait_for_nic(nic_name):
        conn = wmi.WMI(moniker='//./root/cimv2')
        if not conn.Win32_NetworkAdapter(NetConnectionID=nic_name):
            raise exception.ItemNotFoundException(
                "Cannot find NIC: %s" % nic_name)

    @retry_decorator.retry_decorator(max_retry_count=3)
    def add_team_nic(self, team_name, nic_name, vlan_id):
        conn = wmi.WMI(moniker='root/standardcimv2')
        team_nic = conn.MSFT_NetLbfoTeamNIC.new()
        team_nic.Team = team_name
        team_nic.Name = nic_name
        team_nic.VlanID = vlan_id
        team_nic.put()
        # Ensure that the NIC is visible in the OS before returning
        self._wait_for_nic(nic_name)

    @retry_decorator.retry_decorator(max_retry_count=3)
    def delete_team(self, team_name):
        conn = wmi.WMI(moniker='root/standardcimv2')
        teams = conn.MSFT_NetLbfoTeam(name=team_name)
        if not teams:
            raise exception.ItemNotFoundException(
                "Team not found: %s" % team_name)
        teams[0].Delete_()

    @classmethod
    def is_available(cls):
        osutils = osutils_factory.get_os_utils()
        return (sys.platform == 'win32' and osutils.check_os_version(6, 2) and
                not osutils.is_client_os())
