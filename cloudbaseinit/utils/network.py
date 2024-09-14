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


import binascii
import collections
import ipaddress

import netaddr
import socket
import struct
import sys
from urllib import parse
from urllib import request

from oslo_log import log as oslo_logging

from cloudbaseinit.osutils import factory as osutils_factory


LOG = oslo_logging.getLogger(__name__)
MAX_URL_CHECK_RETRIES = 3
DEFAULT_GATEWAY_CIDR_IPV4 = u"0.0.0.0/0"
DEFAULT_GATEWAY_CIDR_IPV6 = u"::/0"
LOCAL_IPV4 = "local-ipv4"
LOCAL_IPV6 = "local-ipv6"


def get_local_ip(address=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((address or "<broadcast>", 8000))
    return s.getsockname()[0]


def check_url(url, retries_count=MAX_URL_CHECK_RETRIES):
    for i in range(0, MAX_URL_CHECK_RETRIES):
        try:
            LOG.debug("Testing url: %s" % url)
            request.urlopen(url)
            return True
        except Exception:
            pass
    return False


def check_metadata_ip_route(metadata_url):
    # Workaround for: https://bugs.launchpad.net/quantum/+bug/1174657
    osutils = osutils_factory.get_os_utils()

    if sys.platform == 'win32' and osutils.check_os_version(6, 0):
        # 169.254.x.x addresses are not getting routed starting from
        # Windows Vista / 2008
        metadata_netloc = parse.urlparse(metadata_url).netloc
        metadata_host = metadata_netloc.split(':')[0]

        if metadata_host.startswith("169.254."):
            if (not osutils.check_static_route_exists(metadata_host) and
                    not check_url(metadata_url)):
                (interface_index, gateway) = osutils.get_default_gateway()
                if gateway:
                    try:
                        LOG.debug('Setting gateway for host: %s',
                                  metadata_host)
                        osutils.add_static_route(metadata_host,
                                                 "255.255.255.255",
                                                 gateway,
                                                 interface_index,
                                                 10)
                    except Exception as ex:
                        # Ignore it
                        LOG.exception(ex)


def address6_to_4_truncate(address6):
    """Try to obtain IPv4 address from version 6."""
    chunks = address6.split(":")
    hi, lo = chunks[-2], chunks[-1]
    network_address = binascii.unhexlify(hi.zfill(4) + lo.zfill(4))
    return socket.inet_ntoa(network_address)


def netmask6_to_4_truncate(netmask6):
    """Try to obtain IPv4 netmask from version 6."""
    # Harsh 128bit to 32bit.
    length = int(int(netmask6) / 4)
    mask = "1" * length + "0" * (32 - length)
    network_address = struct.pack("!L", int(mask, 2))
    return socket.inet_ntoa(network_address)


def ip_netmask_to_cidr(ip_address, netmask):
    if not netmask:
        return ip_address
    prefix_len = netaddr.IPNetwork(
        u"%s/%s" % (ip_address, netmask)).prefixlen
    return u"%s/%s" % (ip_address, prefix_len)


def get_default_ip_addresses(network_details):
    ipv4_address = None
    ipv6_address = None
    if network_details:
        for net in network_details.networks:
            ip_net = netaddr.IPNetwork(net.address_cidr)
            addr = ip_net.ip
            default_route = False
            for route in net.routes:
                if addr.version == 6 and \
                        route.network_cidr == DEFAULT_GATEWAY_CIDR_IPV6:
                    default_route = True

                elif addr.version == 4 and \
                        route.network_cidr == DEFAULT_GATEWAY_CIDR_IPV4:
                    default_route = True

            if not default_route:
                continue

            if not ipv6_address and addr.version == 6:
                v6_addr = ipaddress.IPv6Address(addr)
                if v6_addr.is_private or v6_addr.is_global:
                    ipv6_address = str(v6_addr)

            if not ipv4_address and addr.version == 4:
                v4_addr = ipaddress.IPv4Address(addr)
                if v4_addr.is_private or v4_addr.is_global:
                    ipv4_address = str(v4_addr)

    return ipv4_address, ipv6_address


def get_host_info(hostname, network_details):
    """Returns host information such as the host name and network interfaces.

    """
    host_info = {
        "network": {
            "interfaces": {
                "by-mac": collections.OrderedDict(),
                "by-ipv4": collections.OrderedDict(),
                "by-ipv6": collections.OrderedDict(),
            },
        },
    }
    if hostname:
        host_info["hostname"] = hostname
        host_info["local-hostname"] = hostname
        host_info["local_hostname"] = hostname

    by_mac = host_info["network"]["interfaces"]["by-mac"]
    by_ipv4 = host_info["network"]["interfaces"]["by-ipv4"]
    by_ipv6 = host_info["network"]["interfaces"]["by-ipv6"]

    if not network_details:
        return host_info

    default_ipv4, default_ipv6 = get_default_ip_addresses(network_details)
    if default_ipv4:
        host_info[LOCAL_IPV4] = default_ipv4
        host_info[LOCAL_IPV4.replace('-', '_')] = default_ipv4
    if default_ipv6:
        host_info[LOCAL_IPV6] = default_ipv6
        host_info[LOCAL_IPV6.replace('-', '_')] = default_ipv6

    """
    IPv4: {
            'bcast': '',
            'ip': '127.0.0.1',
            'mask': '255.0.0.0',
            'scope': 'host',
          }
    IPv6: {
            'ip': '::1/128',
            'scope6': 'host'
          }
    """
    mac_by_link_names = {}
    for link in network_details.links:
        mac_by_link_names[link.name] = link.mac_address

    for net in network_details.networks:
        mac = mac_by_link_names[net.link]

        # Do not bother recording localhost
        if mac == "00:00:00:00:00:00":
            continue

        ip_net = netaddr.IPNetwork(net.address_cidr)
        addr = ip_net.ip
        is_v6 = addr.version == 6
        is_v4 = addr.version == 4

        if mac:
            if mac not in by_mac:
                val = {}
            else:
                val = by_mac[mac]
            key = None
            if is_v4:
                key = 'ipv4'
                val[key] = {
                    'addr': str(addr),
                    'netmask': str(ip_net.netmask),
                    'broadcast': str(ip_net.broadcast),
                }
            elif is_v6:
                key = 'ipv6'
                val[key] = {
                    'addr': str(addr),
                    'broadcast': str(ip_net.broadcast),
                }
            if key:
                by_mac[mac] = val

        if is_v4:
            by_ipv4[str(addr)] = {
                'mac': mac,
                'netmask': str(ip_net.netmask),
                'broadcast': str(ip_net.broadcast),
            }

        if is_v6:
            by_ipv6[str(addr)] = {
                'mac': mac,
                'broadcast': str(ip_net.broadcast),
            }

    return host_info
