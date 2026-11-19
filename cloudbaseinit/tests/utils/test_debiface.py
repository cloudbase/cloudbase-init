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

from cloudbaseinit.models import network as network_model
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import debiface

# As written by Proxmox VE (PVE::QemuServer::Cloudinit::configdrive2_network)
# for "ipconfig0: ip=...,gw=...,ip6=...,gw6=..." and "ipconfig1: ip=dhcp,
# ip6=...": the IPv6 settings of an interface get their own inet6 stanza.
PROXMOX_DUAL_STACK = """\
auto lo
iface lo inet loopback

        dns_nameservers 192.0.2.53 2001:db8::53
        dns_search example.com
auto eth0
iface eth0 inet static
        address 192.0.2.10
        netmask 255.255.255.0
        gateway 192.0.2.1
iface eth0 inet6 static
        address 2001:db8:10::10
        netmask 64
        gateway 2001:db8:10::1
auto eth1
iface eth1 inet dhcp
iface eth1 inet6 static
        address 2001:db8:11::10
        netmask 64
"""


class TestInterfacesParser(unittest.TestCase):

    def setUp(self):
        date = "2013-04-04"
        content = fake_json_response.get_fake_metadata_json(date)
        self.data = content["network_config"]["debian_config"]

    def _test_parse_nics(self, no_nics=False):
        with testutils.LogSnatcher('cloudbaseinit.utils.'
                                   'debiface') as snatcher:
            nics = debiface.parse(self.data)

        if no_nics:
            expected_logging = 'Invalid Debian config to parse:'
            self.assertTrue(snatcher.output[0].startswith(expected_logging))
            self.assertFalse(nics)
            return
        # check what we've got
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
        self.assertEqual([nic0, nic1, nic2], nics)

    def test_nothing_to_parse(self):
        invalid = [None, "", 324242, ("dasd", "dsa")]
        for data in invalid:
            self.data = data
            self._test_parse_nics(no_nics=True)

    def test_parse(self):
        self._test_parse_nics()

    def test_parse_inet6_stanza_same_iface(self):
        nics = debiface.parse(PROXMOX_DUAL_STACK)

        fields = ("name", "mac", "address", "netmask", "gateway",
                  "address6", "netmask6", "gateway6")
        found = [tuple(getattr(nic, field) for field in fields)
                 for nic in nics]
        self.assertEqual([
            # The inet6 stanza of eth0 is the IPv6 half of eth0, not a
            # second eth0 which would replace the IPv4 settings.
            ("eth0", None, "192.0.2.10", "255.255.255.0", "192.0.2.1",
             "2001:db8:10::10", "64", "2001:db8:10::1"),
            # No static IPv4 to merge into: unchanged behaviour.
            ("eth1", None, "2001:db8:11::10", "64", None,
             None, None, None),
        ], found)
