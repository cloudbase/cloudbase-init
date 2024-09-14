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

import collections
import unittest
import unittest.mock as mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.models import network as network_model
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import network


CONF = cloudbaseinit_conf.CONF


class NetworkUtilsTest(unittest.TestCase):
    link0 = network_model.Link(
        id="eth0",
        name="eth0",
        type=network_model.LINK_TYPE_PHYSICAL,
        mac_address="ab:cd:ef:ef:cd:ab",
        enabled=None,
        mtu=None,
        bond=None,
        vlan_link=None,
        vlan_id=None,
    )
    network_private_default_route = network_model.Network(
        link="eth0",
        address_cidr="192.168.1.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"0.0.0.0/0",
                gateway="192.168.1.1",
            ),
        ],
        dns_nameservers=[]
    )
    network_public = network_model.Network(
        link="eth0",
        address_cidr="2.3.4.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"2.3.4.1/24",
                gateway="2.3.4.1",
            ),
        ],
        dns_nameservers=[]
    )
    network_public_default_route = network_model.Network(
        link="eth0",
        address_cidr="2.3.4.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"0.0.0.0/0",
                gateway="2.3.4.1",
            ),
        ],
        dns_nameservers=[]
    )
    network_private = network_model.Network(
        link="eth0",
        address_cidr="172.10.1.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"172.10.1.1/24",
                gateway="172.10.1.1",
            ),
        ],
        dns_nameservers=[]
    )
    network_local = network_model.Network(
        link="eth0",
        address_cidr="127.0.0.4/24",
        routes=[
            network_model.Route(
                network_cidr=u"127.0.0.4/24",
                gateway="127.0.0.2",
            ),
        ],
        dns_nameservers=[]
    )
    ipv6_addr = '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38'
    network_v6 = network_model.Network(
        link="eth0",
        address_cidr=ipv6_addr + '/64',
        routes=[network_model.Route(
            network_cidr=u"::/0",
            gateway="::1",
        )],
        dns_nameservers=[]
    )
    ipv6_addr_private = 'fe80::216:3eff:fe16:db54'
    network_v6_local = network_model.Network(
        link="eth0",
        address_cidr=ipv6_addr_private + '/64',
        routes=[],
        dns_nameservers=[]
    )

    @mock.patch('urllib.request.urlopen')
    def test_check_url(self, mock_url_open):
        mock_url_open.return_value = None
        self.assertTrue(network.check_url("fake_url"))

    @mock.patch('sys.platform', new='win32')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('urllib.parse.urlparse')
    def _test_check_metadata_ip_route(self, mock_urlparse, mock_get_os_utils,
                                      side_effect):
        mock_utils = mock.MagicMock()
        mock_split = mock.MagicMock()
        mock_get_os_utils.return_value = mock_utils
        mock_utils.check_os_version.return_value = True
        mock_urlparse().netloc.split.return_value = mock_split
        mock_split[0].startswith.return_value = True
        mock_utils.check_static_route_exists.return_value = False
        mock_utils.get_default_gateway.return_value = (1, '0.0.0.0')
        mock_utils.add_static_route.side_effect = [side_effect]
        network.check_metadata_ip_route('196.254.196.254')
        mock_utils.check_os_version.assert_called_once_with(6, 0)
        mock_urlparse.assert_called_with('196.254.196.254')
        mock_split[0].startswith.assert_called_once_with("169.254.")
        mock_utils.check_static_route_exists.assert_called_once_with(
            mock_split[0])
        mock_utils.get_default_gateway.assert_called_once_with()
        mock_utils.add_static_route.assert_called_once_with(
            mock_split[0], "255.255.255.255", '0.0.0.0', 1, 10)

    def test_test_check_metadata_ip_route(self):
        self._test_check_metadata_ip_route(side_effect=None)

    def test_test_check_metadata_ip_route_fail(self):
        with testutils.LogSnatcher('cloudbaseinit.utils.network') as snatcher:
            self._test_check_metadata_ip_route(side_effect=ValueError)

        self.assertIn('ValueError', snatcher.output[-1])

    def test_address6_to_4_truncate(self):
        address_map = {
            "0:0:0:0:0:ffff:c0a8:f": "192.168.0.15",
            "::ffff:c0a8:e": "192.168.0.14",
            "::1": "0.0.0.1",
            "1:2:3:4:5::8": "0.0.0.8",
            "::": "0.0.0.0",
            "::7f00:1": "127.0.0.1"
        }
        for v6, v4 in address_map.items():
            self.assertEqual(v4, network.address6_to_4_truncate(v6))

    def test_netmask6_to_4_truncate(self):
        netmask_map = {
            "128": "255.255.255.255",
            "96": "255.255.255.0",
            "0": "0.0.0.0",
            "100": "255.255.255.128"
        }
        for v6, v4 in netmask_map.items():
            self.assertEqual(v4, network.netmask6_to_4_truncate(v6))

    @mock.patch('socket.socket')
    def test_get_local_ip(self, mock_socket):
        mock_socket.return_value = mock.Mock()
        mock_socket().getsockname.return_value = ["fake name"]
        res = network.get_local_ip("fake address")
        self.assertEqual(res, "fake name")
        mock_socket().connect.assert_called_with(("fake address", 8000))

    def _test_ip_netmask_to_cidr(self, expected_result, fake_ip_address,
                                 fake_netmask):
        result = network.ip_netmask_to_cidr(fake_ip_address, fake_netmask)
        self.assertEqual(expected_result, result)

    def test_ip_netmask_to_cidr(self):
        fake_ip_address = '10.1.1.1'
        expected_result = '10.1.1.1/24'
        fake_netmask = '255.255.255.0'
        self._test_ip_netmask_to_cidr(expected_result, fake_ip_address,
                                      fake_netmask)

    def test_ip_netmask_to_cidr_empty_netmask(self):
        fake_ip_address = '10.1.1.1'
        fake_netmask = None
        self._test_ip_netmask_to_cidr(fake_ip_address, fake_ip_address,
                                      fake_netmask)

    def test_get_default_ip_addresses(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private_default_route,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertEqual('192.168.1.2', ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_link_local(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertIsNone(ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_public_default_route(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_public_default_route,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertEqual("2.3.4.2", ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_v6(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_v6,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertIsNone(ipv4)
        self.assertEqual(self.ipv6_addr, ipv6)

    def test_get_default_ip_addresses_v6_local(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_v6_local,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertIsNone(ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_dual_stack(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private_default_route,
                self.network_public,
                self.network_v6,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertEqual('192.168.1.2', ipv4)
        self.assertEqual(self.ipv6_addr, ipv6)

    def test_get_host_info(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private_default_route,
                self.network_public, self.network_v6,
            ],
            services=[
            ],
        )
        expect = {
            'hostname': 'fake_host',
            'local-hostname': 'fake_host',
            'local-ipv4': '192.168.1.2',
            'local_ipv4': '192.168.1.2',
            'local-ipv6': '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
            'local_ipv6': '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
            'local_hostname': 'fake_host',
            'network': {'interfaces': {
                'by-ipv4': collections.OrderedDict([
                    ('192.168.1.2',
                     {'broadcast': '192.168.1.255',
                      'mac': 'ab:cd:ef:ef:cd:ab',
                      'netmask': '255.255.255.0'}
                     ),
                    ('2.3.4.2',
                     {'broadcast': '2.3.4.255',
                      'mac': 'ab:cd:ef:ef:cd:ab',
                      'netmask': '255.255.255.0'}
                     )
                ]),
                'by-ipv6': collections.OrderedDict([
                    ('1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
                     {'broadcast': '1a8f:9aaf:2904:858f:ffff:ffff:ffff:ffff',
                      'mac': 'ab:cd:ef:ef:cd:ab',
                      }
                     )
                ]),
                'by-mac': collections.OrderedDict([
                    ('ab:cd:ef:ef:cd:ab',
                     {'ipv4': {'addr': '2.3.4.2',
                               'broadcast': '2.3.4.255',
                               'netmask': '255.255.255.0'},
                      'ipv6': {
                          'addr': '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
                          'broadcast': '1a8f:9aaf:2904:858f:'
                                       'ffff:ffff:ffff:ffff'}
                      }
                     ),
                ])
            }}
        }
        host_info = network.get_host_info('fake_host', network_details)
        self.assertEqual(expect, host_info)
