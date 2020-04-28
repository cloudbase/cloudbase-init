# Copyright 2012 Cloudbase Solutions Srl
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

LINK_TYPE_PHYSICAL = "physical"
LINK_TYPE_BOND = "bond"
LINK_TYPE_VLAN = "vlan"

# Based on: https://www.kernel.org/doc/Documentation/networking/bonding.txts
BOND_TYPE_8023AD = "802.3ad"
BOND_TYPE_BALANCE_RR = "balance-rr"
BOND_TYPE_ACTIVE_BACKUP = "active-backup"
BOND_TYPE_BALANCE_XOR = "balance-xor"
BOND_TYPE_BROADCAST = "broadcast"
BOND_TYPE_BALANCE_TLB = "balance-tlb"
BOND_TYPE_BALANCE_ALB = "balance-alb"

AVAILABLE_BOND_TYPES = [
    BOND_TYPE_8023AD,
    BOND_TYPE_BALANCE_RR,
    BOND_TYPE_ACTIVE_BACKUP,
    BOND_TYPE_BALANCE_XOR,
    BOND_TYPE_BROADCAST,
    BOND_TYPE_BALANCE_TLB,
    BOND_TYPE_BALANCE_ALB,
]

BOND_LB_ALGO_L2 = "layer2"
BOND_LB_ALGO_L2_L3 = "layer2+3"
BOND_LB_ALGO_L3_L4 = "layer3+4"
BOND_LB_ENCAP_L2_L3 = "encap2+3"
BOND_LB_ENCAP_L3_L4 = "encap3+4"

AVAILABLE_BOND_LB_ALGORITHMS = [
    BOND_LB_ALGO_L2,
    BOND_LB_ALGO_L2_L3,
    BOND_LB_ALGO_L3_L4,
    BOND_LB_ENCAP_L2_L3,
    BOND_LB_ENCAP_L3_L4,
]

BOND_LACP_RATE_SLOW = "slow"
BOND_LACP_RATE_FAST = "fast"

AVAILABLE_BOND_LACP_RATES = [
    BOND_LACP_RATE_SLOW,
    BOND_LACP_RATE_FAST
]

NetworkDetails = collections.namedtuple(
    "NetworkDetails",
    [
        "name",
        "mac",
        "address",
        "address6",
        "netmask",
        "netmask6",
        "broadcast",
        "gateway",
        "gateway6",
        "dnsnameservers",
    ]
)


NetworkDetailsV2 = collections.namedtuple(
    "NetworkDetailsV2",
    [
        "links",
        "networks",
        "services"
    ]
)


Link = collections.namedtuple(
    "Link",
    [
        "id",
        "name",
        "type",
        "enabled",
        "mac_address",
        "mtu",
        "bond",
        "vlan_link",
        "vlan_id"
    ]
)


Bond = collections.namedtuple(
    "Bond",
    [
        "members",
        "type",
        "lb_algorithm",
        "lacp_rate"
    ]
)


Network = collections.namedtuple(
    "Network",
    [
        "link",
        "address_cidr",
        "dns_nameservers",
        "routes",
    ]
)


Route = collections.namedtuple(
    "Route",
    [
        "network_cidr",
        "gateway"
    ]
)


NameServerService = collections.namedtuple(
    "NameServerService",
    [
        "addresses",
        "search"
    ]
)
