# Copyright 2020 Cloudbase Solutions Srl
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

import ddt
import importlib
import os
import textwrap
import unittest
import unittest.mock as mock

from cloudbaseinit.metadata.services import base
from cloudbaseinit.models import network as nm
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import serialization

MODULE_PATH = "cloudbaseinit.metadata.services.nocloudservice"
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_EMPTY_CONFIG = """
network:
  version: 1
  t: 1
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_CONFIG_IS_NOT_LIST = """
network:
  version: 1
  config: {
    test: abc
  }
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_CONFIG_ITEM_IS_NOT_DICT = """
network:
  version: 1
  config:
  - ['test', 'abc']
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_ROUTER_CONFIG_NOT_SUPPORTED = """
network:
  version: 1
  config:
  - type: router
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_LEGACY = """
version: 1
config:
- type: physical
  name: interface0
  mac_address: "52:54:00:12:34:00"
  mtu: 1450
  subnets:
  - type: static
    address: 192.168.1.10
    netmask: 255.255.255.0
    gateway: 192.168.1.1
    dns_nameservers:
    - 192.168.1.11
- type: bond
  name: bond0
  bond_interfaces:
  - gbe0
  - gbe1
  mac_address: "52:54:00:12:34:00"
  params:
    bond-mode: active-backup
    bond-lacp-rate: false
  mtu: 1450
  subnets:
  - type: static
    address: 192.168.1.10
    netmask: 255.255.255.0
    dns_nameservers:
    - 192.168.1.11
- type: vlan
  name: vlan0
  vlan_link: eth1
  vlan_id: 150
  mac_address: "52:54:00:12:34:00"
  mtu: 1450
  subnets:
  - type: static
    address: 192.168.1.10
    netmask: 255.255.255.0
    dns_nameservers:
    - 192.168.1.11
- type: nameserver
  address:
  - 192.168.23.2
  - 8.8.8.8
  search: acme.local
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1 = """
network:%s
""" % (textwrap.indent(NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_LEGACY, "  "))
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_EMPTY_CONFIG = """
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_CONFIG_IS_NOT_DICT = """
network:
- config
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_IS_NOT_DICT = """
network:
  version: 2
  ethernets:
  - test
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_SETTING_IS_NOT_DICT = """
network:
  version: 2
  ethernets:
    eth0:
     - test
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_LEGACY = """
version: 2
ethernets:
  interface0:
    match:
      macaddress: "52:54:00:12:34:00"
    set-name: "eth0"
    addresses:
    - 192.168.1.10/24
    gateway4: 192.168.1.1
    nameservers:
      addresses:
      - 192.168.1.11
      - 192.168.1.12
      search:
      - acme.local
    mtu: 1450
  interface1:
    set-name: "interface1"
    addresses:
    - 192.168.1.100/24
    gateway4: 192.168.1.1
    nameservers:
      addresses:
      - 192.168.1.11
      - 192.168.1.12
      search:
      - acme.local
bonds:
  bond0:
    interfaces: ["gbe0", "gbe1"]
    match:
      macaddress: "52:54:00:12:34:00"
    parameters:
      mode: active-backup
      lacp-rate: false
    addresses:
    - 192.168.1.10/24
    nameservers:
      addresses:
      - 192.168.1.11
    mtu: 1450
vlans:
  vlan0:
    id: 150
    link: eth1
    dhcp4: yes
    match:
      macaddress: "52:54:00:12:34:00"
    addresses:
    - 192.168.1.10/24
    nameservers:
      addresses:
      - 192.168.1.11
    mtu: 1450
bridges:
  br0:
    interfaces: ['eth0']
    dhcp4: true
"""
NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2 = """
network:%s
""" % (textwrap.indent(NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_LEGACY, "  "))


@ddt.ddt
class TestNoCloudNetworkConfigV1Parser(unittest.TestCase):
    def setUp(self):
        module = importlib.import_module(MODULE_PATH)
        self._parser = module.NoCloudNetworkConfigV1Parser()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @ddt.data(
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_EMPTY_CONFIG,
            ('Network configuration is empty', None)),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_CONFIG_IS_NOT_LIST,
         ("is not a list", None)),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_CONFIG_ITEM_IS_NOT_DICT,
         ("is not a dictionary",
          nm.NetworkDetailsV2(links=[], networks=[], services=[]))),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_ROUTER_CONFIG_NOT_SUPPORTED,
         ("Network config type 'router' is not supported",
          nm.NetworkDetailsV2(links=[], networks=[], services=[])))
    )
    @ddt.unpack
    def test_parse_empty_result(self, input, expected_result):

        with self.snatcher:
            result = self._parser.parse(serialization.parse_json_yaml(input))

        self.assertEqual(True, expected_result[0] in self.snatcher.output[0])
        self.assertEqual(result, expected_result[1])

    @ddt.data(
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1, True),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V1_LEGACY, True)
    )
    @ddt.unpack
    def test_network_details_v2(self, test_data, expected_result):
        expected_bond = nm.Bond(
            members=["gbe0", "gbe1"],
            type=nm.BOND_TYPE_ACTIVE_BACKUP,
            lb_algorithm=None,
            lacp_rate=None,
        )
        expected_link_bond = nm.Link(
            id='bond0',
            name='bond0',
            type=nm.LINK_TYPE_BOND,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=expected_bond,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link = nm.Link(
            id='interface0',
            name='interface0',
            type=nm.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link_vlan = nm.Link(
            id='vlan0',
            name='vlan0',
            type=nm.LINK_TYPE_VLAN,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link='eth1',
            vlan_id=150,
        )
        expected_network = nm.Network(
            link='interface0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[
                nm.Route(network_cidr='0.0.0.0/0',
                         gateway="192.168.1.1")
            ]
        )

        expected_network_bond = nm.Network(
            link='bond0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )

        expected_network_vlan = nm.Network(
            link='vlan0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )
        expected_nameservers = nm.NameServerService(
            addresses=['192.168.23.2', '8.8.8.8'],
            search='acme.local')

        result = self._parser.parse(
            serialization.parse_json_yaml(test_data))

        self.assertEqual(result.links[0], expected_link)
        self.assertEqual(result.networks[0], expected_network)

        self.assertEqual(result.links[1], expected_link_bond)
        self.assertEqual(result.networks[1], expected_network_bond)

        self.assertEqual(result.links[2], expected_link_vlan)
        self.assertEqual(result.networks[2], expected_network_vlan)

        self.assertEqual(result.services[0], expected_nameservers)


@ddt.ddt
class TestNoCloudNetworkConfigV2Parser(unittest.TestCase):
    def setUp(self):
        module = importlib.import_module(MODULE_PATH)
        self._parser = module.NoCloudNetworkConfigV2Parser()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @ddt.data(
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_EMPTY_CONFIG,
         ('Network configuration is empty', None)),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_CONFIG_IS_NOT_DICT,
         ('is not a dict', None)),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_IS_NOT_DICT,
         ('is not a dict',
          nm.NetworkDetailsV2(links=[], networks=[], services=[])),
         ),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_SETTING_IS_NOT_DICT,
         ('of type ethernet is not a dict',
          nm.NetworkDetailsV2(links=[], networks=[], services=[])),
         )
    )
    @ddt.unpack
    def test_parse_empty_result(self, input, expected_result):
        with self.snatcher:
            result = self._parser.parse(serialization.parse_json_yaml(input))

        self.assertEqual(True, expected_result[0] in self.snatcher.output[0])
        self.assertEqual(result, expected_result[1])

    @ddt.data(
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2, True),
        (NOCLOUD_NETWORK_CONFIG_TEST_DATA_V2_LEGACY, True)
    )
    @ddt.unpack
    def test_network_details_v2(self, test_data, expected_result):
        expected_bond = nm.Bond(
            members=["gbe0", "gbe1"],
            type=nm.BOND_TYPE_ACTIVE_BACKUP,
            lb_algorithm=None,
            lacp_rate=None,
        )
        expected_link_bond = nm.Link(
            id='bond0',
            name='bond0',
            type=nm.LINK_TYPE_BOND,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=expected_bond,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link = nm.Link(
            id='interface0',
            name='eth0',
            type=nm.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link_if1 = nm.Link(
            id='interface1',
            name='interface1',
            type=nm.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address=None,
            mtu=None,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link_vlan = nm.Link(
            id='vlan0',
            name='vlan0',
            type=nm.LINK_TYPE_VLAN,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link='eth1',
            vlan_id=150,
        )
        expected_network = nm.Network(
            link='eth0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11', '192.168.1.12'],
            routes=[
                nm.Route(network_cidr='0.0.0.0/0',
                         gateway="192.168.1.1")
            ]
        )
        expected_network_if1 = nm.Network(
            link='interface1',
            address_cidr='192.168.1.100/24',
            dns_nameservers=['192.168.1.11', '192.168.1.12'],
            routes=[
                nm.Route(network_cidr='0.0.0.0/0',
                         gateway="192.168.1.1")
            ]
        )

        expected_network_bond = nm.Network(
            link='bond0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )

        expected_network_vlan = nm.Network(
            link='vlan0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )
        expected_nameservers = nm.NameServerService(
            addresses=['192.168.1.11', '192.168.1.12'],
            search='acme.local')

        result = self._parser.parse(
            serialization.parse_json_yaml(test_data))

        self.assertEqual(result.links[0], expected_link)
        self.assertEqual(result.links[1], expected_link_if1)
        self.assertEqual(result.networks[0], expected_network)
        self.assertEqual(result.networks[1], expected_network_if1)

        self.assertEqual(result.links[2], expected_link_bond)
        self.assertEqual(result.networks[2], expected_network_bond)

        self.assertEqual(result.links[3], expected_link_vlan)
        self.assertEqual(result.networks[3], expected_network_vlan)

        self.assertEqual(result.services[0], expected_nameservers)


@ddt.ddt
class TestNoCloudConfigDriveService(unittest.TestCase):

    def setUp(self):
        self._win32com_mock = mock.MagicMock()
        self._ctypes_mock = mock.MagicMock()
        self._ctypes_util_mock = mock.MagicMock()
        self._win32com_client_mock = mock.MagicMock()
        self._pywintypes_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'win32com': self._win32com_mock,
             'ctypes': self._ctypes_mock,
             'ctypes.util': self._ctypes_util_mock,
             'win32com.client': self._win32com_client_mock,
             'pywintypes': self._pywintypes_mock})
        self._module_patcher.start()
        self.addCleanup(self._module_patcher.stop)

        self.configdrive_module = importlib.import_module(MODULE_PATH)
        self._config_drive = (
            self.configdrive_module.NoCloudConfigDriveService())
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @mock.patch('os.path.normpath')
    @mock.patch('os.path.join')
    def test_get_data(self, mock_join, mock_normpath):
        fake_path = os.path.join('fake', 'path')
        with mock.patch('builtins.open',
                        mock.mock_open(read_data='fake data'), create=True):
            response = self._config_drive._get_data(fake_path)
            self.assertEqual('fake data', response)
            mock_join.assert_called_with(
                self._config_drive._metadata_path, fake_path)
            mock_normpath.assert_called_once_with(mock_join.return_value)

    @mock.patch('shutil.rmtree')
    def test_cleanup(self, mock_rmtree):
        fake_path = os.path.join('fake', 'path')
        self._config_drive._metadata_path = fake_path
        mock_mgr = mock.Mock()
        self._config_drive._mgr = mock_mgr
        mock_mgr.target_path = fake_path
        self._config_drive.cleanup()
        mock_rmtree.assert_called_once_with(fake_path,
                                            ignore_errors=True)
        self.assertEqual(None, self._config_drive._metadata_path)

    @mock.patch(MODULE_PATH + '.NoCloudConfigDriveService._get_meta_data')
    def test_get_public_keys(self, mock_get_metadata):
        fake_key = 'fake key'
        expected_result = [fake_key]
        mock_get_metadata.return_value = {
            'public-keys': {
                '0': {
                    'openssh-key': fake_key
                }
            }
        }
        result = self._config_drive.get_public_keys()
        self.assertEqual(result, expected_result)

    @mock.patch(MODULE_PATH + '.NoCloudConfigDriveService._get_meta_data')
    def test_get_public_keys_alt_fmt(self, mock_get_metadata):
        fake_key = 'fake key'
        expected_result = [fake_key]
        mock_get_metadata.return_value = {
            'public-keys': [fake_key]
        }
        result = self._config_drive.get_public_keys()
        self.assertEqual(result, expected_result)

    @ddt.data(('', ('V2 network metadata is empty', None)),
              ('1', ('V2 network metadata is not a dictionary', None)),
              ('{}', ('V2 network metadata is empty', None)),
              ('{}}', ('V2 network metadata could not be deserialized', None)),
              (base.NotExistingMetadataException('exc'),
               ('V2 network metadata not found', True)))
    @ddt.unpack
    @mock.patch(MODULE_PATH + '.NoCloudConfigDriveService._get_cache_data')
    def test_network_details_v2_empty_result(self, input, expected_result,
                                             mock_get_cache_data):
        if expected_result[1]:
            mock_get_cache_data.side_effect = [input]
        else:
            mock_get_cache_data.return_value = input
        with self.snatcher:
            result = self._config_drive.get_network_details_v2()
        self.assertEqual(True, expected_result[0] in self.snatcher.output[0])
        self.assertEqual(result, None)

        mock_get_cache_data.assert_called_with(
            "network-config", decode=True)
