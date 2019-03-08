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


import functools
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.models import network as network_model
from cloudbaseinit.plugins.common import base as plugin_base
from cloudbaseinit.plugins.common import networkconfig
from cloudbaseinit.tests import testutils


class TestNetworkConfigPlugin(unittest.TestCase):

    def setUp(self):
        self._setup_network_details_v1()

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def _test_execute_network_details_v1(self, mock_get_os_utils,
                                         network_adapters=None,
                                         network_details=None,
                                         invalid_details=False,
                                         missed_adapters=[],
                                         extra_network_details=[]):
        # Prepare mock environment.
        mock_service = mock.MagicMock()
        mock_shared_data = mock.Mock()
        mock_osutils = mock.MagicMock()
        mock_service.get_network_details.return_value = network_details
        mock_service.get_network_details_v2.return_value = None
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.get_network_adapters.return_value = network_adapters
        mock_osutils.set_static_network_config.return_value = True

        mock_osutils.get_network_adapter_name_by_mac_address = (
            lambda mac: [n[0] for n in network_adapters if n[1] == mac][0])

        network_execute = functools.partial(
            self._network_plugin.execute,
            mock_service, mock_shared_data
        )
        # Actual tests.
        if not network_details:
            ret = network_execute()
            self.assertEqual((plugin_base.PLUGIN_EXECUTION_DONE, False), ret)
            return
        if invalid_details or not network_adapters:
            with self.assertRaises(exception.CloudbaseInitException):
                network_execute()
            return
        # Good to go for the configuration process.
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'common.networkconfig'):
            ret = network_execute()

        calls = []
        for adapter in set(network_adapters) - set(missed_adapters):
            nics = [nic for nic in (network_details +
                                    extra_network_details)
                    if nic.mac == adapter[1]]
            self.assertTrue(nics)    # missed_adapters should do the job
            nic = nics[0]
            call = mock.call(
                adapter[0],
                nic.address,
                nic.netmask,
                nic.gateway,
                nic.dnsnameservers
            )
            call6 = mock.call(
                adapter[0],
                nic.address6,
                nic.netmask6,
                nic.gateway6,
                []
            )
            if nic.address and nic.netmask:
                calls.append(call)
            if nic.address6 and nic.netmask6:
                calls.append(call6)
        self.assertEqual(
            len(calls),
            mock_osutils.set_static_network_config.call_count)
        mock_osutils.set_static_network_config.assert_has_calls(
            calls, any_order=True)
        reboot = len(missed_adapters) != self._count
        self.assertEqual((plugin_base.PLUGIN_EXECUTION_DONE, reboot), ret)

    def _setup_network_details_v1(self, same_names=True, wrong_names=False,
                                  no_macs=False):
        # Generate fake pairs of NetworkDetails objects and
        # local ethernet network adapters.
        iface_name = "Ethernet" if wrong_names else "eth"
        self._count = 3
        details_names = ["{}{}".format(iface_name, idx)
                         for idx in range(self._count)]
        if same_names:
            adapters_names = details_names[:]
        else:
            adapters_names = ["vm " + name for name in details_names]
        macs = [
            "54:EE:75:19:F4:61",
            "54:EE:75:19:F4:62",
            "54:EE:75:19:F4:63"
        ]
        addresses = [
            "192.168.122.101",
            "192.168.103.104",
            "192.168.122.105",
        ]
        addresses6 = [
            "::ffff:c0a8:7a65",
            "::ffff:c0a8:6768",
            "::ffff:c0a8:7a69"
        ]
        netmasks = [
            "255.255.255.0",
            "255.255.0.0",
            "255.255.255.128",
        ]
        netmasks6 = [
            "96",
            "64",
            "100"
        ]
        broadcasts = [
            "192.168.122.255",
            "192.168.255.255",
            "192.168.122.127",
        ]
        gateways = [
            "192.168.122.1",
            "192.168.122.16",
            "192.168.122.32",
        ]
        gateways6 = [
            "::ffff:c0a8:7a01",
            "::ffff:c0a8:7a10",
            "::ffff:c0a8:7a20"
        ]
        dnsnses = [
            "8.8.8.8",
            "8.8.8.8 8.8.4.4",
            "8.8.8.8 0.0.0.0",
        ]
        self._network_adapters = []
        self._network_details = []
        for ind in range(self._count):
            adapter = (adapters_names[ind], macs[ind])
            nic = network_model.NetworkDetails(
                details_names[ind],
                None if no_macs else macs[ind],
                addresses[ind],
                addresses6[ind],
                netmasks[ind],
                netmasks6[ind],
                broadcasts[ind],
                gateways[ind],
                gateways6[ind],
                dnsnses[ind].split()
            )
            self._network_adapters.append(adapter)
            self._network_details.append(nic)
        # Get the network config plugin.
        self._network_plugin = networkconfig.NetworkConfigPlugin()
        # Execution wrapper.
        self._partial_test_execute_network_details_v1 = functools.partial(
            self._test_execute_network_details_v1,
            network_adapters=self._network_adapters,
            network_details=self._network_details
        )

    def test_execute_no_network_details(self):
        self._network_details[:] = []
        self._partial_test_execute_network_details_v1()

    def test_execute_no_network_adapters(self):
        self._network_adapters[:] = []
        self._partial_test_execute_network_details_v1()

    def test_execute_invalid_network_details(self):
        self._network_details.append([None] * 6)
        self._partial_test_execute_network_details_v1(invalid_details=True)

    def test_execute_invalid_network_details_name(self):
        self._setup_network_details_v1(wrong_names=True, no_macs=True)
        self._partial_test_execute_network_details_v1(invalid_details=True)

    def test_execute_single(self):
        for _ in range(self._count - 1):
            self._network_adapters.pop()
            self._network_details.pop()
        self._partial_test_execute_network_details_v1()

    def test_execute_multiple(self):
        self._partial_test_execute_network_details_v1()

    def test_execute_missing_one(self):
        self.assertGreater(self._count, 1)
        self._network_details.pop(0)
        adapter = self._network_adapters[0]
        self._partial_test_execute_network_details_v1(
            missed_adapters=[adapter])

    def test_execute_missing_all(self):
        nic = self._network_details[0]
        nic = network_model.NetworkDetails(
            nic.name,
            "00" + nic.mac[2:],
            nic.address,
            nic.address6,
            nic.netmask,
            nic.netmask6,
            nic.broadcast,
            nic.gateway,
            nic.gateway6,
            nic.dnsnameservers
        )
        self._network_details[:] = [nic]
        self._partial_test_execute_network_details_v1(
            missed_adapters=self._network_adapters)

    def _test_execute_missing_smth(self, name=False, mac=False,
                                   address=False, address6=False,
                                   netmask=False, netmask6=False,
                                   gateway=False, fail=False):
        ind = self._count - 1
        nic = self._network_details[ind]
        nic2 = network_model.NetworkDetails(
            None if name else nic.name,
            None if mac else nic.mac,
            None if address else nic.address,
            None if address6 else nic.address6,
            None if netmask else nic.netmask,
            None if netmask6 else nic.netmask6,
            nic.broadcast,
            None if gateway else nic.gateway,
            None if gateway else nic.gateway6,
            nic.dnsnameservers
        )
        self._network_details[ind] = nic2
        # Excluding address and gateway switches...
        if not fail:
            # Even this way, all adapters should be configured.
            missed_adapters = []
            extra_network_details = [nic]
        else:
            # Both name and MAC are missing, so we can't make the match.
            # Or other vital details.
            missed_adapters = [self._network_adapters[ind]]
            extra_network_details = []
        self._partial_test_execute_network_details_v1(
            missed_adapters=missed_adapters,
            extra_network_details=extra_network_details
        )

    def test_execute_missing_mac(self):
        self._test_execute_missing_smth(mac=True)

    def test_execute_missing_mac2(self):
        self._setup_network_details_v1(same_names=False)
        self._test_execute_missing_smth(mac=True)

    def test_execute_missing_name_mac(self):
        self._test_execute_missing_smth(name=True, mac=True, fail=True)

    def test_execute_missing_address(self):
        self._test_execute_missing_smth(address=True)

    def test_execute_missing_netmask(self):
        self._test_execute_missing_smth(netmask=True)

    def test_execute_missing_address6(self):
        self._test_execute_missing_smth(address6=True)

    def test_execute_missing_netmask6(self):
        self._test_execute_missing_smth(netmask6=True)

    def test_execute_missing_address_netmask6(self):
        self._test_execute_missing_smth(address=True, netmask6=True,
                                        fail=True)

    def test_execute_missing_gateway(self):
        self._test_execute_missing_smth(gateway=True)

    def _get_network_details_v2(self):
        links = []
        link1 = network_model.Link(
            id=mock.sentinel.link_id1,
            name=mock.sentinel.link_name1,
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=mock.sentinel.link_enabled1,
            mac_address=mock.sentinel.link_mac1,
            mtu=mock.sentinel.link_mtu1,
            bond=None,
            vlan_link=None,
            vlan_id=None)
        links.append(link1)

        bond1 = network_model.Bond(
            members=[mock.sentinel.link_id1],
            type=mock.sentinel.bond_type1,
            lb_algorithm=mock.sentinel.bond_lb_algo1,
            lacp_rate=mock.sentinel.lacp_rate1)

        bond_link1 = network_model.Link(
            id=mock.sentinel.bond_link_id1,
            name=mock.sentinel.bond_link_name1,
            type=network_model.LINK_TYPE_BOND,
            enabled=mock.sentinel.bond_link_enabled1,
            mac_address=mock.sentinel.bond_link_mac1,
            mtu=mock.sentinel.bond_link_mtu1,
            bond=bond1,
            vlan_link=None,
            vlan_id=None)
        links.append(bond_link1)

        vlan_link1 = network_model.Link(
            id=mock.sentinel.vlan_link_id1,
            name=mock.sentinel.vlan_link_name1,
            type=network_model.LINK_TYPE_VLAN,
            enabled=mock.sentinel.vlan_link_enabled1,
            mac_address=mock.sentinel.vlan_link_mac1,
            mtu=mock.sentinel.vlan_link_mtu1,
            bond=None,
            vlan_link=mock.sentinel.bond_link_id1,
            vlan_id=mock.sentinel.vlan_id1)
        links.append(vlan_link1)

        networks = []
        route1 = network_model.Route(
            network_cidr=mock.sentinel.network_cidr1,
            gateway=mock.sentinel.gateway1)

        route2 = network_model.Route(
            network_cidr=mock.sentinel.network_cidr2,
            gateway=mock.sentinel.gateway2)

        network1 = network_model.Network(
            link=mock.sentinel.link_id1,
            address_cidr=mock.sentinel.address_cidr1,
            dns_nameservers=mock.sentinel.network_dns_list1,
            routes=[route1, route2])
        networks.append(network1)

        services = []
        service1 = network_model.NameServerService(
            addresses=[mock.sentinel.dns1, mock.sentinel.dns3],
            search=mock.sentinel.dns_search1)
        services.append(service1)

        return network_model.NetworkDetailsV2(
            links=links, networks=networks, services=services)

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def _test_execute_network_details_v2(self, mock_get_os_utils,
                                         empty_network_dns_list=False,
                                         both_ipv4_dns_list=False,
                                         both_ipv6_dns_list=False):
        mock.sentinel.link_mac1 = u"00:00:00:00:00:01"
        mock.sentinel.network_cidr1 = u"0.0.0.0/0"
        mock.sentinel.gateway1 = u"10.0.0.254"
        mock.sentinel.network_cidr2 = u"172.16.0.0/16"
        mock.sentinel.gateway2 = u"172.16.1.1"
        mock.sentinel.address_cidr1 = u"10.0.0.1/24"
        mock.sentinel.dns1 = "10.0.0.1"
        mock.sentinel.dns2 = "10.0.0.2"
        mock.sentinel.network_dns_list1 = []

        if empty_network_dns_list:
            mock.sentinel.dns3 = "10.0.0.3"
            expected_dns_list = [mock.sentinel.dns1, mock.sentinel.dns3]
        elif both_ipv4_dns_list:
            mock.sentinel.dns3 = "2001:db8::3"
            expected_dns_list = [mock.sentinel.dns1]
        elif both_ipv6_dns_list:
            mock.sentinel.address_cidr1 = u"2001:db8::3/24"
            mock.sentinel.dns3 = "2001:db8::4"
            expected_dns_list = [mock.sentinel.dns3]
        else:
            mock.sentinel.network_dns_list1 = [
                mock.sentinel.dns1, mock.sentinel.dns2]
            expected_dns_list = mock.sentinel.network_dns_list1

        service = mock.Mock()
        network_details = self._get_network_details_v2()
        service.get_network_details_v2.return_value = network_details

        mock_os_utils = mock.Mock()
        mock_get_os_utils.return_value = mock_os_utils

        m = mock_os_utils.get_network_adapter_name_by_mac_address
        m.return_value = mock.sentinel.adapter_old_name1

        plugin = networkconfig.NetworkConfigPlugin()
        plugin.execute(service, {})

        service.get_network_details_v2.assert_called_once_with()
        service.get_network_details.assert_not_called()

        m.assert_called_once_with(mock.sentinel.link_mac1)

        mock_os_utils.rename_network_adapter.assert_called_once_with(
            mock.sentinel.adapter_old_name1, mock.sentinel.link_name1)

        bond_name = (networkconfig.BOND_FORMAT_STR %
                     mock.sentinel.bond_link_id1)
        mock_os_utils.create_network_team.assert_called_once_with(
            bond_name, mock.sentinel.bond_type1,
            mock.sentinel.bond_lb_algo1,
            [mock.sentinel.link_id1],
            mock.sentinel.bond_link_mac1,
            mock.sentinel.bond_link_name1,
            None,
            mock.sentinel.lacp_rate1)

        mock_os_utils.add_network_team_nic.assert_called_once_with(
            bond_name,
            mock.sentinel.vlan_link_name1,
            mock.sentinel.vlan_id1)

        mock_os_utils.set_network_adapter_mtu.assert_has_calls(
            [mock.call(mock.sentinel.link_name1, mock.sentinel.link_mtu1),
             mock.call(
                mock.sentinel.bond_link_name1, mock.sentinel.bond_link_mtu1),
             mock.call(
                mock.sentinel.vlan_link_name1, mock.sentinel.vlan_link_mtu1)],
            any_order=False)

        mock_os_utils.enable_network_adapter.assert_has_calls(
            [mock.call(mock.sentinel.link_name1, mock.sentinel.link_enabled1),
             mock.call(
                mock.sentinel.bond_link_name1,
                mock.sentinel.bond_link_enabled1),
             mock.call(
                mock.sentinel.vlan_link_name1,
                mock.sentinel.vlan_link_enabled1)],
            any_order=False)

        ip_address, prefix_len = mock.sentinel.address_cidr1.split("/")
        mock_os_utils.set_static_network_config.assert_called_once_with(
            mock.sentinel.link_id1, ip_address, prefix_len,
            mock.sentinel.gateway1, expected_dns_list)

    def test_execute_network_details_v2(self):
        self._test_execute_network_details_v2()

    def test_execute_network_details_v2_empty_network_dns_list(self):
        self._test_execute_network_details_v2(empty_network_dns_list=True)

    def test_execute_network_details_v2_ipv4_dns_list(self):
        self._test_execute_network_details_v2(both_ipv4_dns_list=True)

    def test_execute_network_details_v2_ipv6_dns_list(self):
        self._test_execute_network_details_v2(both_ipv6_dns_list=True)
