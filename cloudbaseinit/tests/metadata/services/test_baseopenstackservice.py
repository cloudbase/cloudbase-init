# Copyright 2014 Cloudbase Solutions Srl
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
import posixpath
import unittest

import netaddr

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.models import network as network_model
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.utils import x509constants


CONF = cloudbaseinit_conf.CONF

MODPATH = "cloudbaseinit.metadata.services.baseopenstackservice"


class FinalBaseOpenStackService(baseopenstackservice.BaseOpenStackService):

    def _get_data(self):
        pass


class TestBaseOpenStackService(unittest.TestCase):

    def setUp(self):
        CONF.set_override("retry_count_interval", 0)
        self._service = FinalBaseOpenStackService()
        date = "2013-04-04"
        fake_metadata = fake_json_response.get_fake_metadata_json(date)
        self._fake_network_config = fake_metadata["network_config"]
        self._fake_content = self._fake_network_config["debian_config"]
        self._fake_public_keys = fake_metadata["public_keys"]
        self._fake_keys = fake_metadata["keys"]
        self._partial_test_get_network_details = functools.partial(
            self._test_get_network_details,
            network_config=self._fake_network_config,
            content=self._fake_content
        )

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_cache_data")
    def test_get_content(self, mock_get_cache_data):
        response = self._service.get_content('fake name')
        path = posixpath.join('openstack', 'content', 'fake name')
        mock_get_cache_data.assert_called_once_with(path)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._service.get_user_data()
        path = posixpath.join('openstack', 'latest', 'user_data')
        mock_get_cache_data.assert_called_once_with(path)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_cache_data")
    def test_get_meta_data(self, mock_get_cache_data):
        mock_get_cache_data.return_value = '{"fake": "data"}'
        response = self._service._get_meta_data(
            version='fake version')
        path = posixpath.join('openstack', 'fake version', 'meta_data.json')
        mock_get_cache_data.assert_called_with(path, decode=True)
        self.assertEqual({"fake": "data"}, response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def test_get_instance_id(self, mock_get_meta_data):
        response = self._service.get_instance_id()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('uuid')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def test_get_host_name(self, mock_get_meta_data):
        response = self._service.get_host_name()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('hostname')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def test_get_public_keys(self, mock_get_meta_data):
        mock_get_meta_data.return_value.get.side_effect = \
            [self._fake_public_keys, self._fake_keys]
        response = self._service.get_public_keys()

        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data.return_value.get.assert_any_call("public_keys")
        mock_get_meta_data.return_value.get.assert_any_call("keys")

        public_keys = (list(self._fake_public_keys.values()) +
                       [key["data"] for key in self._fake_keys
                        if key["type"] == "ssh"])
        public_keys = [key.strip() for key in public_keys]

        self.assertEqual(sorted(list(set(public_keys))),
                         sorted(response))

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def _test_get_admin_username(self, mock_get_meta_data, meta_data):
        mock_get_meta_data.return_value = meta_data
        response = self._service.get_admin_username()
        mock_get_meta_data.assert_called_once_with()
        if meta_data and 'admin_username' in meta_data.get('meta'):
            self.assertEqual(meta_data.get('meta')['admin_username'], response)
        else:
            self.assertIsNone(response)

    def test_get_admin_username_in_meta(self):
        self._test_get_admin_username(
            meta_data={'meta': {'admin_username': 'fake user'}})

    def test_get_admin_username_no_username_in_meta(self):
        self._test_get_admin_username(meta_data={'meta': {}})

    def test_get_admin_username_no_meta_data(self):
        self._test_get_admin_username(meta_data={})

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def _test_get_admin_password(self, mock_get_meta_data, meta_data):
        mock_get_meta_data.return_value = meta_data
        response = self._service.get_admin_password()
        mock_get_meta_data.assert_called_once_with()
        if meta_data and 'admin_pass' in meta_data:
            self.assertEqual(meta_data['admin_pass'], response)
        elif meta_data and 'admin_pass' in meta_data.get('meta'):
            self.assertEqual(meta_data.get('meta')['admin_pass'], response)
        else:
            self.assertIsNone(response)

    def test_get_admin_pass(self):
        self._test_get_admin_password(meta_data={'admin_pass': 'fake pass'})

    def test_get_admin_pass_in_meta(self):
        self._test_get_admin_password(
            meta_data={'meta': {'admin_pass': 'fake pass'}})

    def test_get_admin_pass_no_pass(self):
        self._test_get_admin_password(meta_data={})

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    @mock.patch(MODPATH +
                ".BaseOpenStackService.get_user_data")
    def _test_get_client_auth_certs(self, mock_get_user_data,
                                    mock_get_meta_data, meta_data,
                                    ret_value=None):
        mock_get_meta_data.return_value = meta_data
        mock_get_user_data.side_effect = [ret_value]
        response = self._service.get_client_auth_certs()
        mock_get_meta_data.assert_called_once_with()
        if isinstance(ret_value, bytes) and ret_value.startswith(
                x509constants.PEM_HEADER.encode()):
            mock_get_user_data.assert_called_once_with()
            self.assertEqual([ret_value.decode()], response)
        elif ret_value is base.NotExistingMetadataException:
            self.assertFalse(response)
        else:
            expected = []
            expectation = {
                "meta": 'fake cert',
                "keys": [key["data"].strip() for key in self._fake_keys
                         if key["type"] == "x509"]
            }
            for field, value in expectation.items():
                if field in meta_data:
                    expected.extend(value if isinstance(value, list)
                                    else [value])
            self.assertEqual(sorted(list(set(expected))), sorted(response))

    def test_get_client_auth_certs(self):
        self._test_get_client_auth_certs(
            meta_data={'meta': {'admin_cert0': 'fake ',
                                'admin_cert1': 'cert'},
                       "keys": self._fake_keys})

    def test_get_client_auth_certs_no_cert_data(self):
        self._test_get_client_auth_certs(
            meta_data={}, ret_value=x509constants.PEM_HEADER.encode())

    def test_get_client_auth_certs_no_cert_data_exception(self):
        self._test_get_client_auth_certs(
            meta_data={}, ret_value=base.NotExistingMetadataException)

    @mock.patch(MODPATH +
                ".BaseOpenStackService.get_content")
    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def _test_get_network_details(self,
                                  mock_get_meta_data,
                                  mock_get_content,
                                  network_config=None,
                                  content=None,
                                  search_fail=False,
                                  no_path=False):
        # mock obtained data
        mock_get_meta_data().get.return_value = network_config
        mock_get_content.return_value = content
        # actual tests
        if search_fail:
            ret = self._service.get_network_details()
            self.assertFalse(ret)
            return
        ret = self._service.get_network_details()
        mock_get_meta_data().get.assert_called_once_with("network_config")
        if network_config and not no_path:
            mock_get_content.assert_called_once_with("network")
        if not network_config:
            self.assertIsNone(ret)
            return
        if no_path:
            self.assertIsNone(ret)
            return
        # check returned NICs details
        nic0 = network_model.NetworkDetails(
            fake_json_response.NAME0,
            fake_json_response.MAC0.upper(),
            fake_json_response.ADDRESS0,
            fake_json_response.ADDRESS60,
            fake_json_response.NETMASK0,
            fake_json_response.NETMASK60,
            fake_json_response.BROADCAST0,
            fake_json_response.GATEWAY0,
            fake_json_response.GATEWAY60,
            fake_json_response.DNSNS0.split()
        )
        nic1 = network_model.NetworkDetails(
            fake_json_response.NAME1,
            None,
            fake_json_response.ADDRESS1,
            fake_json_response.ADDRESS61,
            fake_json_response.NETMASK1,
            fake_json_response.NETMASK61,
            fake_json_response.BROADCAST1,
            fake_json_response.GATEWAY1,
            fake_json_response.GATEWAY61,
            None
        )
        nic2 = network_model.NetworkDetails(
            fake_json_response.NAME2,
            None,
            fake_json_response.ADDRESS2,
            fake_json_response.ADDRESS62,
            fake_json_response.NETMASK2,
            fake_json_response.NETMASK62,
            fake_json_response.BROADCAST2,
            fake_json_response.GATEWAY2,
            fake_json_response.GATEWAY62,
            None
        )
        self.assertEqual([nic0, nic1, nic2], ret)

    def test_get_network_details_no_config(self):
        self._partial_test_get_network_details(
            network_config=None
        )

    def test_get_network_details_no_path(self):
        self._fake_network_config.pop("content_path", None)
        self._partial_test_get_network_details(
            network_config=self._fake_network_config,
            no_path=True
        )

    def test_get_network_details_search_fail(self):
        self._fake_content = "invalid format"
        self._partial_test_get_network_details(
            content=self._fake_content,
            search_fail=True
        )

    def test_get_network_details(self):
        self._partial_test_get_network_details()

    @staticmethod
    def _get_network_data():
        return {
            "links": [{
                "ethernet_mac_address": mock.sentinel.link_mac1,
                "type": baseopenstackservice.NETWORK_LINK_TYPE_PHYSICAL,
                "id": mock.sentinel.link_id1,
                "mtu": mock.sentinel.link_mtu1,
            }, {
                "ethernet_mac_address": mock.sentinel.link_mac2,
                "type": mock.sentinel.another_link_type,
                "id": mock.sentinel.link_id2,
                "mtu": mock.sentinel.link_mtu2,
            }, {
                "bond_miimon": mock.sentinel.bond_miimon1,
                "bond_xmit_hash_policy": mock.sentinel.bond_lb_algo1,
                "ethernet_mac_address": mock.sentinel.bond_mac1,
                "mtu": mock.sentinel.bond_mtu1,
                "bond_mode": mock.sentinel.bond_type1,
                "bond_links": [
                    mock.sentinel.link_id1,
                    mock.sentinel.link_id2,
                ],
                "type": baseopenstackservice.NETWORK_LINK_TYPE_BOND,
                "id": mock.sentinel.bond_id1,
            }, {
                "id": mock.sentinel.vlan_link_id1,
                "type": baseopenstackservice.NETWORK_LINK_TYPE_VLAN,
                "vlan_link": mock.sentinel.bond_id1,
                "vlan_id": mock.sentinel.vlan_id1,
                "mtu": mock.sentinel.vlan_mtu1,
                "ethernet_mac_address": mock.sentinel.vlan_mac1,
            }],
            "networks": [{
                "id": mock.sentinel.network_id1,
                "network_id": mock.sentinel.network_openstack_id1,
                "link": mock.sentinel.bond_id1,
                "type": baseopenstackservice.NETWORK_TYPE_IPV4_DHCP,
            }, {
                "id": mock.sentinel.network_id2,
                "type": baseopenstackservice.NETWORK_TYPE_IPV4,
                "link": mock.sentinel.bond_id1,
                "ip_address": mock.sentinel.ip_address1,
                "netmask": mock.sentinel.netmask1,
                "services": [{
                    "type": baseopenstackservice.NETWORK_SERVICE_TYPE_DNS,
                    "address": mock.sentinel.dns1,
                }, {
                    "type": baseopenstackservice.NETWORK_SERVICE_TYPE_DNS,
                    "address": mock.sentinel.dns2
                }],
                "routes": [{
                    "network": mock.sentinel.route_network1,
                    "netmask": mock.sentinel.route_netmask1,
                    "gateway": mock.sentinel.route_gateway1,
                }, {
                    "network": mock.sentinel.route_network2,
                    "netmask": mock.sentinel.route_netmask2,
                    "gateway": mock.sentinel.route_gateway2,
                }],
                "network_id": mock.sentinel.network_openstack_id2
            }, {
                "id": mock.sentinel.network_id3,
                "type": baseopenstackservice.NETWORK_TYPE_IPV6,
                "link": mock.sentinel.bond_id1,
                "ip_address": mock.sentinel.ip_address_ipv61,
                "routes": [{
                    "network": mock.sentinel.route_network_ipv61,
                    "gateway": mock.sentinel.route_gateway_ipv61,
                }],
                "network_id": mock.sentinel.network_openstack_id3
            }],
            "services": [{
                "type": baseopenstackservice.NETWORK_SERVICE_TYPE_DNS,
                "address": mock.sentinel.dns3,
            }, {
                "type": baseopenstackservice.NETWORK_SERVICE_TYPE_DNS,
                "address": mock.sentinel.dns4
            }],
        }

    @mock.patch(MODPATH + ".BaseOpenStackService._get_network_data")
    def _test_get_network_details_v2(self, mock_get_network_data,
                                     invalid_bond_type=False,
                                     invalid_bond_lb_algo=False):
        mock.sentinel.ip_address1 = "10.0.0.1"
        mock.sentinel.netmask1 = "255.255.255.0"
        mock.sentinel.route_network1 = "172.16.0.0"
        mock.sentinel.route_netmask1 = "255.255.0.0"
        mock.sentinel.route_gateway1 = "172.16.1.1"
        mock.sentinel.route_network2 = "0.0.0.0"
        mock.sentinel.route_netmask2 = "0.0.0.0"
        mock.sentinel.route_gateway2 = "10.0.0.254"
        mock.sentinel.ip_address_ipv61 = "2001:cdba::3257:9652/24"
        mock.sentinel.route_network_ipv61 = "::/0"
        mock.sentinel.route_gateway_ipv61 = "fd00::1"

        if invalid_bond_type:
            mock.sentinel.bond_type1 = "invalid bond type"
        else:
            mock.sentinel.bond_type1 = network_model.BOND_TYPE_ACTIVE_BACKUP

        if invalid_bond_lb_algo:
            mock.sentinel.bond_lb_algo1 = "invalid lb algorithm"
        else:
            mock.sentinel.bond_lb_algo1 = network_model.BOND_LB_ALGO_L2

        network_data = self._get_network_data()

        mock_get_network_data.return_value = network_data

        if invalid_bond_type or invalid_bond_lb_algo:
            with self.assertRaises(exception.CloudbaseInitException):
                self._service.get_network_details_v2()
            return

        network_details = self._service.get_network_details_v2()

        self.assertEqual(
            len(network_data["links"]), len(network_details.links))

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_PHYSICAL and
            l.id == mock.sentinel.link_id1 and
            l.name == mock.sentinel.link_id1 and
            l.mac_address == mock.sentinel.link_mac1 and
            l.mtu == mock.sentinel.link_mtu1]))

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_PHYSICAL and
            l.id == mock.sentinel.link_id2 and
            l.name == mock.sentinel.link_id2 and
            l.mac_address == mock.sentinel.link_mac2 and
            l.mtu == mock.sentinel.link_mtu2]))

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_BOND and
            l.id == mock.sentinel.bond_id1 and
            l.name == mock.sentinel.bond_id1 and
            l.mtu == mock.sentinel.bond_mtu1 and
            l.mac_address == mock.sentinel.bond_mac1 and
            l.vlan_link is None and
            l.vlan_id is None and
            l.bond.type == network_model.BOND_TYPE_ACTIVE_BACKUP and
            l.bond.members == [
                mock.sentinel.link_id1, mock.sentinel.link_id2] and
            l.bond.lb_algorithm == network_model.BOND_LB_ALGO_L2 and
            l.bond.lacp_rate is None]))

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_VLAN and
            l.id == mock.sentinel.vlan_link_id1 and
            l.name == mock.sentinel.vlan_link_id1 and
            l.mac_address == mock.sentinel.vlan_mac1 and
            l.mtu == mock.sentinel.vlan_mtu1 and
            l.vlan_link == mock.sentinel.bond_id1 and
            l.vlan_id == mock.sentinel.vlan_id1]))

        self.assertEqual(
            len([n for n in network_data["networks"]
                 if n["type"] in [
                     baseopenstackservice.NETWORK_TYPE_IPV4,
                     baseopenstackservice.NETWORK_TYPE_IPV6]]),
            len(network_details.networks))

        def _get_cidr_address(ip_address, netmask):
            prefix_len = netaddr.IPNetwork(
                u"%s/%s" % (ip_address, netmask)).prefixlen
            return u"%s/%s" % (ip_address, prefix_len)

        address_cidr = _get_cidr_address(
            mock.sentinel.ip_address1, mock.sentinel.netmask1)

        network = [
            n for n in network_details.networks
            if n.address_cidr == address_cidr and
            n.dns_nameservers == [mock.sentinel.dns1, mock.sentinel.dns2] and
            n.link == mock.sentinel.bond_id1]
        self.assertEqual(1, len(network))

        network_cidr1 = _get_cidr_address(
            mock.sentinel.route_network1, mock.sentinel.route_netmask1)

        network_cidr2 = _get_cidr_address(
            mock.sentinel.route_network2, mock.sentinel.route_netmask2)

        self.assertEqual([
            network_model.Route(
                network_cidr=network_cidr1,
                gateway=mock.sentinel.route_gateway1),
            network_model.Route(
                network_cidr=network_cidr2,
                gateway=mock.sentinel.route_gateway2)],
            network[0].routes)

        network_ipv6 = [
            n for n in network_details.networks
            if n.address_cidr == mock.sentinel.ip_address_ipv61 and
            n.link == mock.sentinel.bond_id1]
        self.assertEqual(1, len(network_ipv6))

        self.assertEqual(
            [network_model.NameServerService(
                addresses=[mock.sentinel.dns3, mock.sentinel.dns4],
                search=None)],
            network_details.services)

    def test_get_network_details_v2(self):
        self._test_get_network_details_v2()

    def test_get_network_details_v2_invalid_bond_type(self):
        self._test_get_network_details_v2(invalid_bond_type=True)

    def test_get_network_details_v2_invalid_bond_lb_algo(self):
        self._test_get_network_details_v2(invalid_bond_lb_algo=True)

    @mock.patch(MODPATH + ".BaseOpenStackService._get_network_data")
    @mock.patch(MODPATH + ".LOG.info")
    def test_get_network_details_v2_no_metadata(self, mock_log_exception,
                                                mock_get_network_data):
        mock_get_network_data.side_effect = (
            base.NotExistingMetadataException('failed to get metadata'))
        network_details = self._service.get_network_details_v2()

        self.assertIsNone(network_details)
        self.assertTrue(mock_log_exception.called)
