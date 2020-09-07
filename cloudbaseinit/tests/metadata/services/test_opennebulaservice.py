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


import re
import textwrap
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import opennebulaservice
from cloudbaseinit.models import network as network_model
from cloudbaseinit.tests import testutils


MAC = "54:EE:75:19:F4:61"    # output must be upper
ADDRESS = "192.168.122.101"
NETMASK = "255.255.255.0"
BROADCAST = "192.168.122.255"
GATEWAY = "192.168.122.1"
DNSNS = "8.8.8.8 8.8.4.4"
PUBLIC_KEY = ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDJitRvac/fr1jWrZw"
              "j6mgDxlrBN2xAtKExtm5cPkexQUuxTma61ZijP/aWiQg9Q93baSwsBi"
              "IPM0SO1ro0szv84cC9GmSHWVOnCVWGY3nojplqL5VfV9NDLlmSceFc5"
              "cLpUTMnoUiXt8QXfDm50gh/5vGgJJXuMz1BKwfJH232ajM5r9xUfKDZ"
              "jzhTVooPlWoJJmn6xJDOJG7cjszZpv2N+Xzq7GRo6fa7ygTASOnES5t"
              "vbcqM8432P6Bg7Hkr2bOjQF11RyJofFcOvECKfbX4jQ9JGzbocNnepw"
              "2YlV08UYa/8aoFgzyo/FiR6cc/jQupbFIe92xBSNiMEioeZ26nTac6C"
              "oRQXEKrb95Ntg7ysYUqjKQFWJdx6AW7hlE8mMjA6nRqvswXsp1atNdU"
              "DylyVxlvUHo9rEHEs3GKjkO4tr8KKR0N+oWVAO8S2RfSaD/wFcTokW8"
              "DeLz2Fnc04pyqOnCjdG7b7HqQVUupuxJNc3EUxZEjbUYiDi22MWF0Oa"
              "vM7e0xZHMOsdhUPUUnBWngETuOTVSo26bRfzOcUzjwyv2n5PS9rvzYz"
              "ooXIqcK4BdJ8TLh4OQZwV862PjiafxxWC1L90Tou+BkMTFvwoiWDGMc"
              "ckPkjvg6p9E2viSFgaKMq2S6EjbzsHG/9BilLBDHLOcbhUU6E76dqGk"
              "4jl0ZzQ== jfontan@zooloo")
HOST_NAME = "ws2012r2"
USER_DATA = """#cloud-config
bootcmd:
  - ifdown -a
runcmd:
  - curl http://10.0.1.1:8999/I_am_alive
write_files:
-   encoding: b64
    content: RG9lcyBpdCB3b3JrPwo=
    owner: root:root
    path: /etc/test_file
    permissions: '\''0644'\''
packages:
  - ruby2.0"""

CONTEXT = """
DISK_ID='1'
ETH0_DNS='{dnsns}'
ETH0_GATEWAY='{gateway}'
ETH0_IP='{address}'
ETH0_MASK='{netmask}'
ETH0_MAC='{mac}'
ETH0_SEARCH_DOMAIN='example.org'
NETWORK='YES'
SET_HOSTNAME='{host_name}'
SSH_PUBLIC_KEY='{public_key}'
TARGET='hda'
USER_DATA='{user_data}'
""".format(
    dnsns=DNSNS,
    gateway=GATEWAY,
    address=ADDRESS,
    netmask=NETMASK,
    mac=MAC.lower(),    # warning: mac is in lowercase
    host_name=HOST_NAME,
    public_key=PUBLIC_KEY,
    user_data=USER_DATA
)

CONTEXT2 = ("""
ETH1_DNS='{dnsns}'
ETH1_GATEWAY='{gateway}'
ETH1_IP='{address}'
ETH1_MASK='{netmask}'
ETH1_MAC='{mac}'
""" + CONTEXT).format(
    dnsns=DNSNS,
    gateway=GATEWAY,
    address=ADDRESS,
    netmask=NETMASK,
    mac=MAC.lower()
)

OPEN = mock.mock_open(read_data=CONTEXT.encode())


def _get_nic_details(iid=0):
        details = network_model.NetworkDetails(
            opennebulaservice.IF_FORMAT.format(iid=iid),
            MAC,
            ADDRESS,
            None,
            NETMASK,
            None,
            BROADCAST,
            GATEWAY,
            None,
            DNSNS.split(" ")
        )
        return details


class _TestOpenNebulaService(unittest.TestCase):

    def setUp(self):
        self._service = opennebulaservice.OpenNebulaService()


@mock.patch("six.moves.builtins.open", new=OPEN)
class TestOpenNebulaService(_TestOpenNebulaService):

    @classmethod
    def setUpClass(cls):
        OPEN.return_value.read.return_value = CONTEXT.encode()

    def _test_parse_shell_variables(self, crlf=False, comment=False):
        content = textwrap.dedent("""
            VAR1='1'
            var2='abcdef'
            VAR_VAR3='aaa.bbb.123.ccc'
            # suddenly, a comment
            VaR4='aaa
            bbb
            x -- c
            d: e
            '
            ivar=10
            TESTEMPTY=''
            TESTEMPTY2=""
        """)
        if comment:
            content += "# A simple comment\n"
        if crlf:
            content = content.replace("\n", "\r\n")
        pairs = self._service._parse_shell_variables(content.encode())
        _pairs = {
            "TESTEMPTY": b"",
            "TESTEMPTY2": b"",
            "VAR1": b"1",
            "var2": b"abcdef",
            "VAR_VAR3": b"aaa.bbb.123.ccc",
            "VaR4": b"aaa\nbbb\nx -- c\nd: e\n",
            "ivar": 10
        }
        if crlf:
            for key, value in _pairs.items():
                if isinstance(value, bytes):
                    _pairs[key] = value.replace(b"\n", b"\r\n")
        self.assertEqual(_pairs, pairs)

    def test_parse_shell_variables(self):
        # 1. no CRLF, no comment
        # 2. CRLF, no comment
        # 3. no CRLF, comment
        for crlf, comment in (
                (False, False),
                (True, False),
                (False, True)):
            self._test_parse_shell_variables(crlf=crlf, comment=comment)

    def test_calculate_netmask(self):
        address, gateway, _netmask = (
            "192.168.0.10",
            "192.168.1.1",
            "255.255.0.0"
        )
        netmask = self._service._calculate_netmask(address, gateway)
        self.assertEqual(_netmask, netmask)

    def test_compute_broadcast(self):
        address, netmask, _broadcast = (
            "192.168.0.10",
            "255.255.0.0",
            "192.168.255.255"
        )
        broadcast = self._service._compute_broadcast(address, netmask)
        self.assertEqual(_broadcast, broadcast)

    @mock.patch("cloudbaseinit.metadata.services"
                ".opennebulaservice.os.path")
    @mock.patch("cloudbaseinit.metadata.services"
                ".opennebulaservice.osutils_factory")
    def _test_load(self, mock_osutils_factory, mock_os_path, level=0):
        # fake data
        fakes = {
            "drive": "mount_point",
            "label": "fake_label",
            "context_path": "fake_path",
            "context_data": "fake_data"
        }
        # mocking part
        mock_osutils = mock.MagicMock()
        mock_osutils_factory.get_os_utils.return_value = mock_osutils
        mock_osutils.get_cdrom_drives.return_value = []
        # custom mocking according to level of testing
        if level > 1:
            mock_osutils.get_cdrom_drives.return_value = [fakes["drive"]]
            mock_osutils.get_volume_label.return_value = fakes["label"]
            mock_os_path.join.return_value = fakes["context_path"]
            mock_os_path.isfile.return_value = False
            if level > 2:
                mock_os_path.isfile.return_value = True
        # run the method being tested
        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'opennebulaservice'):
            ret = self._service.load()
        # check calls
        if level > 0:
            mock_osutils_factory.get_os_utils.assert_called_once_with()
            mock_osutils.get_cdrom_drives.assert_called_once_with()
            if level > 1:
                (mock_osutils.get_volume_label
                    .assert_called_once_with(fakes["drive"]))
                mock_os_path.join.assert_called_once_with(
                    "mount_point", opennebulaservice.CONTEXT_FILE)
                mock_os_path.isfile.assert_called_once_with("fake_path")
        # check response and members
        if level in (1, 2):
            self.assertFalse(ret)
        elif level == 3:
            self.assertTrue(ret)
            self.assertEqual(fakes["context_path"],
                             self._service._context_path)

    def test_load_no_drives(self):
        self._test_load(level=1)

    def test_load_no_relevant_drive(self):
        self._test_load(level=2)

    def test_load_relevant_drive(self):
        self._test_load(level=3)

    def test_parse_context(self):
        with self.assertRaises(base.NotExistingMetadataException):
            self._service._parse_context()
        self._service._context_path = "path"
        self._service._parse_context()
        open.assert_called_with("path", "rb")
        self.assertTrue(self._service._dict_content)

    def test_get_data(self):
        self._service._context_path = "path"
        self._service._parse_context()
        with self.assertRaises(base.NotExistingMetadataException):
            self._service._get_data("smt")
        var = opennebulaservice.ADDRESS[0].format(iid=0)
        ret = self._service._get_data(var).decode()
        self.assertEqual(ADDRESS, ret)


class TestLoadedOpenNebulaService(_TestOpenNebulaService):

    def setUp(self):
        super(TestLoadedOpenNebulaService, self).setUp()
        self.load_context()

    def load_context(self, context=CONTEXT):
        self._service._raw_content = context.encode()
        vardict = self._service._parse_shell_variables(
            self._service._raw_content
        )
        self._service._dict_content = vardict

    def test_get_cache_data(self):
        names = ["smt"]
        with self.assertRaises(base.NotExistingMetadataException):
            self._service._get_cache_data(names)
        names.append(opennebulaservice.ADDRESS[0].format(iid=0))
        ret = self._service._get_cache_data(names).decode()
        self.assertEqual(ADDRESS, ret)

    def test_get_instance_id(self):
        self.assertEqual(
            opennebulaservice.INSTANCE_ID,
            self._service.get_instance_id()
        )

    def test_get_host_name(self):
        self.assertEqual(
            HOST_NAME,
            self._service.get_host_name()
        )

    def test_get_user_data(self):
        self.assertEqual(
            USER_DATA.encode(),
            self._service.get_user_data()
        )

    def test_get_public_keys(self):
        self.assertEqual(
            [PUBLIC_KEY],
            self._service.get_public_keys()
        )

    def _test_get_network_details(self, netmask=True):
        if not netmask:
            context = re.sub(r"ETH0_MASK='(\d+\.){3}\d+'", "", CONTEXT)
            self.load_context(context=context)
        details = _get_nic_details()
        self.assertEqual(
            [details],
            self._service.get_network_details()
        )

    def test_get_network_details(self):
        self._test_get_network_details(netmask=True)

    def test_get_network_details_predict(self):
        self._test_get_network_details(netmask=False)

    def test_multiple_nics(self):
        self.load_context(context=CONTEXT2)
        nic0 = _get_nic_details(iid=0)
        nic1 = _get_nic_details(iid=1)
        network_details = [nic0, nic1]
        self.assertEqual(
            network_details,
            self._service.get_network_details()
        )

    @mock.patch("cloudbaseinit.metadata.services"
                ".opennebulaservice.OpenNebulaService._get_cache_data")
    def test_get_network_details_exception(self, mock_get_cache):
        mock_mac = mock_address = mock.MagicMock()
        mock_mac.upper.return_value = None
        mock_address.side_effect = None
        exc = base.NotExistingMetadataException
        mock_get_cache.side_effect = [mock_mac, mock_address, exc, exc]
        result_details = self._service.get_network_details()
        self.assertEqual(result_details, [])
