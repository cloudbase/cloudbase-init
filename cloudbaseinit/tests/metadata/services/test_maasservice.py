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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import maasservice
from cloudbaseinit.models import network as network_model
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import x509constants


CONF = cloudbaseinit_conf.CONF


class MaaSHttpServiceTest(unittest.TestCase):

    def setUp(self):
        self._maasservice = maasservice.MaaSHttpService()

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def _test_load(self, mock_get_cache_data, ip, cache_data_fails=False):
        if cache_data_fails:
            mock_get_cache_data.side_effect = Exception

        with testutils.ConfPatcher('metadata_base_url', ip, "maas"):
            with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                       'maasservice') as snatcher:
                response = self._maasservice.load()

            if ip is not None:
                if not cache_data_fails:
                    mock_get_cache_data.assert_called_once_with(
                        '%s/meta-data/' % self._maasservice._metadata_version)
                    self.assertTrue(response)
                else:
                    expected_logging = 'Metadata not found at URL \'%s\'' % ip
                    self.assertEqual(expected_logging, snatcher.output[-1])
            else:
                self.assertFalse(response)

    def test_load(self):
        self._test_load(ip='196.254.196.254')

    def test_load_no_ip(self):
        self._test_load(ip=None)

    def test_load_get_cache_data_fails(self):
        self._test_load(ip='196.254.196.254', cache_data_fails=True)

    @testutils.ConfPatcher('oauth_consumer_key', 'consumer_key', "maas")
    @testutils.ConfPatcher('oauth_consumer_secret', 'consumer_secret', "maas")
    @testutils.ConfPatcher('oauth_token_key', 'token_key', "maas")
    @testutils.ConfPatcher('oauth_token_secret', 'token_secret', "maas")
    def test_get_oauth_headers(self):
        response = self._maasservice._get_oauth_headers(url='196.254.196.254')
        self.assertIsInstance(response, dict)
        self.assertIn('Authorization', response)

        auth = response['Authorization']
        self.assertTrue(auth.startswith('OAuth'))

        auth = auth[6:]
        parts = [item.strip() for item in auth.split(",")]
        auth_parts = dict(part.split("=") for part in parts)

        required_headers = {
            'oauth_token',
            'oauth_consumer_key',
            'oauth_signature',
        }
        self.assertTrue(required_headers.issubset(set(auth_parts)))
        self.assertEqual('"token_key"', auth_parts['oauth_token'])
        self.assertEqual('"consumer_key"', auth_parts['oauth_consumer_key'])
        self.assertEqual('"consumer_secret%26token_secret"',
                         auth_parts['oauth_signature'])

    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseHTTPMetadataService._http_request')
    @mock.patch('cloudbaseinit.metadata.services.maasservice.MaaSHttpService'
                '._get_oauth_headers')
    def test_http_request(self, mock_ouath_headers, mock_http_request):
        mock_url = "fake.url"
        self._maasservice._http_request(mock_url)
        mock_http_request.assert_called_once_with(mock_url, None, {}, None)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_host_name(self, mock_get_cache_data):
        response = self._maasservice.get_host_name()
        mock_get_cache_data.assert_called_once_with(
            '%s/meta-data/local-hostname' %
            self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_instance_id(self, mock_get_cache_data):
        response = self._maasservice.get_instance_id()
        mock_get_cache_data.assert_called_once_with(
            '%s/meta-data/instance-id' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_public_keys(self, mock_get_cache_data):
        public_keys = [
            "fake key 1",
            "fake key 2"
        ]
        public_key = "\n".join(public_keys) + "\n"
        mock_get_cache_data.return_value = public_key
        response = self._maasservice.get_public_keys()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/public-keys' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(public_keys, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_client_auth_certs(self, mock_get_cache_data):
        certs = [
            "{begin}\n{cert}\n{end}".format(
                begin=x509constants.PEM_HEADER,
                end=x509constants.PEM_FOOTER,
                cert=cert)
            for cert in ("first cert", "second cert")
        ]
        mock_get_cache_data.return_value = "\n".join(certs) + "\n"
        response = self._maasservice.get_client_auth_certs()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/x509' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(certs, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._maasservice.get_user_data()
        mock_get_cache_data.assert_called_once_with(
            '%s/user-data' %
            self._maasservice._metadata_version)
        self.assertEqual(mock_get_cache_data.return_value, response)

    def _get_network_data(self):
        return {
            "version": mock.sentinel.network_data_version,
            "config": [{
                "mtu": mock.sentinel.link_mtu1,
                "name": mock.sentinel.link_name1,
                "subnets": [{
                    "type": maasservice.MAAS_SUBNET_TYPE_MANUAL
                }],
                "type": maasservice.MAAS_CONFIG_TYPE_PHYSICAL,
                "mac_address": mock.sentinel.link_mac1,
                "id": mock.sentinel.link_id1
            }, {
                "mtu": mock.sentinel.link_mtu2,
                "name": mock.sentinel.link_name2,
                "subnets": [{
                    "type": maasservice.MAAS_SUBNET_TYPE_MANUAL
                }],
                "type": maasservice.MAAS_CONFIG_TYPE_PHYSICAL,
                "mac_address": mock.sentinel.link_mac2,
                "id": mock.sentinel.link_id2
            }, {
                "mtu": mock.sentinel.link_mtu3,
                "name": mock.sentinel.link_name3,
                "subnets": [{
                    "type": maasservice.MAAS_SUBNET_TYPE_MANUAL
                }],
                "type": maasservice.MAAS_CONFIG_TYPE_PHYSICAL,
                "mac_address": mock.sentinel.link_mac3,
                "id": mock.sentinel.link_id3
            }, {
                "name": mock.sentinel.bond_name1,
                "id": mock.sentinel.bond_id1,
                "type": maasservice.MAAS_CONFIG_TYPE_BOND,
                "mac_address": mock.sentinel.bond_mac1,
                "bond_interfaces": [
                    mock.sentinel.link_id1,
                    mock.sentinel.link_id2
                ],
                "mtu": mock.sentinel.bond_mtu1,
                "subnets": [{
                    "address": mock.sentinel.bond_subnet_address1,
                    "gateway": mock.sentinel.bond_subnet_gateway1,
                    "type": maasservice.MAAS_SUBNET_TYPE_STATIC,
                    "dns_nameservers": [
                        mock.sentinel.bond_subnet_dns1,
                        mock.sentinel.bond_subnet_dns2]
                }, {
                    "address": mock.sentinel.bond_subnet_address2,
                    "type": maasservice.MAAS_SUBNET_TYPE_STATIC,
                    "dns_nameservers": []
                }],
                "params": {
                    "bond-downdelay": 0,
                    "bond-xmit-hash-policy": mock.sentinel.bond_lb_algo1,
                    "bond-mode": mock.sentinel.bond_mode1,
                    "bond-updelay": 0,
                    "bond-miimon": 100,
                    "bond-lacp-rate": maasservice.MAAS_BOND_LACP_RATE_FAST
                }
            }, {
                "type": maasservice.MAAS_CONFIG_TYPE_VLAN,
                "mtu": mock.sentinel.vlan_mtu1,
                "name": mock.sentinel.vlan_name1,
                "subnets": [{
                    "gateway": mock.sentinel.vlan_subnet_gateway1,
                    "address": mock.sentinel.vlan_subnet_address1,
                    "type": maasservice.MAAS_SUBNET_TYPE_STATIC,
                    "dns_nameservers": []
                }],
                "vlan_id": mock.sentinel.vlan_id1,
                "vlan_link": mock.sentinel.bond_id1,
                "id": mock.sentinel.vlan_link_id1
            }, {
                "type": mock.sentinel.nameserver_config_type,
                "search": [
                    mock.sentinel.dns_search1
                ],
                "address": [
                    mock.sentinel.bond_subnet_dns1,
                    mock.sentinel.bond_subnet_dns2
                ],
            }]
        }

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_network_data")
    def _test_get_network_details_v2(self, mock_get_network_data,
                                     unsupported_version=False,
                                     invalid_bond_type=False,
                                     invalid_bond_lb_algo=False,
                                     unsupported_config_type=False):
        mock.sentinel.bond_subnet_address1 = "10.0.0.1/24"
        mock.sentinel.bond_subnet_gateway1 = "10.0.0.254"
        mock.sentinel.bond_subnet_address2 = "172.16.0.1/16"
        mock.sentinel.vlan_subnet_address1 = "2001:cdba::3257:9652/24"
        mock.sentinel.vlan_subnet_gateway1 = "2001:cdba::3257:1"

        if invalid_bond_type:
            mock.sentinel.bond_mode1 = "invalid bond type"
        else:
            mock.sentinel.bond_mode1 = network_model.BOND_TYPE_BALANCE_ALB

        if invalid_bond_lb_algo:
            mock.sentinel.bond_lb_algo1 = "invalid lb algorithm"
        else:
            mock.sentinel.bond_lb_algo1 = network_model.BOND_LB_ALGO_L2

        if unsupported_version:
            mock.sentinel.network_data_version = "unsupported"
        else:
            mock.sentinel.network_data_version = 1

        if unsupported_config_type:
            mock.sentinel.nameserver_config_type = "unsupported"
        else:
            mock.sentinel.nameserver_config_type = "nameserver"

        network_data = self._get_network_data()
        mock_get_network_data.return_value = network_data

        if (unsupported_version or invalid_bond_type or invalid_bond_lb_algo or
                unsupported_config_type):
            with self.assertRaises(exception.CloudbaseInitException):
                self._maasservice.get_network_details_v2()
            return

        network_details = self._maasservice.get_network_details_v2()

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_PHYSICAL and
            l.id == mock.sentinel.link_id1 and
            l.name == mock.sentinel.link_name1 and
            l.enabled is True and
            l.mac_address == mock.sentinel.link_mac1 and
            l.mtu == mock.sentinel.link_mtu1]))

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_PHYSICAL and
            l.id == mock.sentinel.link_id2 and
            l.name == mock.sentinel.link_name2 and
            l.enabled is True and
            l.mac_address == mock.sentinel.link_mac2 and
            l.mtu == mock.sentinel.link_mtu2]))

        # Disconnected network adapter, ensure it's not enabled
        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_PHYSICAL and
            l.id == mock.sentinel.link_id3 and
            l.name == mock.sentinel.link_name3 and
            l.enabled is False and
            l.mac_address == mock.sentinel.link_mac3 and
            l.mtu == mock.sentinel.link_mtu3]))

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_BOND and
            l.id == mock.sentinel.bond_id1 and
            l.enabled is True and
            l.name == mock.sentinel.bond_name1 and
            l.mtu == mock.sentinel.bond_mtu1 and
            l.mac_address == mock.sentinel.bond_mac1 and
            l.vlan_link is None and
            l.vlan_id is None and
            l.bond.type == network_model.BOND_TYPE_BALANCE_ALB and
            l.bond.members == [
                mock.sentinel.link_id1, mock.sentinel.link_id2] and
            l.bond.lb_algorithm == network_model.BOND_LB_ALGO_L2 and
            l.bond.lacp_rate == network_model.BOND_LACP_RATE_FAST]))

        self.assertEqual(1, len([
            l for l in network_details.links if
            l.type == network_model.LINK_TYPE_VLAN and
            l.id == mock.sentinel.vlan_link_id1 and
            l.name == mock.sentinel.vlan_name1 and
            l.enabled is True and
            l.mac_address is None and
            l.mtu == mock.sentinel.vlan_mtu1 and
            l.vlan_link == mock.sentinel.bond_id1 and
            l.vlan_id == mock.sentinel.vlan_id1]))

        self.assertEqual(3, len(network_details.networks))

        network_bond1 = [
            n for n in network_details.networks
            if n.address_cidr == mock.sentinel.bond_subnet_address1 and
            n.dns_nameservers == [
                mock.sentinel.bond_subnet_dns1,
                mock.sentinel.bond_subnet_dns2] and
            n.link == mock.sentinel.bond_id1 and
            n.routes == [network_model.Route(
                network_cidr=u'0.0.0.0/0',
                gateway=mock.sentinel.bond_subnet_gateway1
            )]]
        self.assertEqual(1, len(network_bond1))

        network_bond2 = [
            n for n in network_details.networks
            if n.address_cidr == mock.sentinel.bond_subnet_address2 and
            n.dns_nameservers == [] and
            n.link == mock.sentinel.bond_id1 and
            n.routes == []]
        self.assertEqual(1, len(network_bond2))

        network_vlan1 = [
            n for n in network_details.networks
            if n.address_cidr == mock.sentinel.vlan_subnet_address1 and
            n.dns_nameservers == [] and
            n.link == mock.sentinel.vlan_link_id1 and
            n.routes == [network_model.Route(
                network_cidr=u'::/0',
                gateway=mock.sentinel.vlan_subnet_gateway1
            )]]
        self.assertEqual(1, len(network_vlan1))

        self.assertEqual(
            [network_model.NameServerService(
                addresses=[
                    mock.sentinel.bond_subnet_dns1,
                    mock.sentinel.bond_subnet_dns2],
                search=[mock.sentinel.dns_search1])],
            network_details.services)

    def test_get_network_details_v2(self):
        self._test_get_network_details_v2()

    def test_get_network_details_v2_unsupported_version(self):
        self._test_get_network_details_v2(unsupported_version=True)

    def test_get_network_details_v2_unsupported_config_type(self):
        self._test_get_network_details_v2(unsupported_config_type=True)

    def test_get_network_details_v2_invalid_bond_type(self):
        self._test_get_network_details_v2(invalid_bond_type=True)

    def test_get_network_details_v2_invalid_bond_lb_algo(self):
        self._test_get_network_details_v2(invalid_bond_lb_algo=True)
