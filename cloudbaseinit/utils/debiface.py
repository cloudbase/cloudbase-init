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

from oslo_log import log as oslo_logging
import six

from cloudbaseinit.models import network as network_model


LOG = oslo_logging.getLogger(__name__)

NAME = "name"
MAC = "mac"
ADDRESS = "address"
ADDRESS6 = "address6"
NETMASK = "netmask"
NETMASK6 = "netmask6"
BROADCAST = "broadcast"
GATEWAY = "gateway"
GATEWAY6 = "gateway6"
DNSNS = "dnsnameservers"
# Fields of interest by regexps.
FIELDS = {
    NAME: re.compile(r"iface\s+(?P<{}>\S+)"
                     r"\s+inet6?\s+static".format(NAME)),
    MAC: re.compile(r"hwaddress\s+ether\s+"
                    r"(?P<{}>\S+)".format(MAC)),
    ADDRESS: re.compile(r"address\s+"
                        r"(?P<{}>\S+)".format(ADDRESS)),
    ADDRESS6: re.compile(r"post-up ip -6 addr add (?P<{}>[^/]+)/"
                         r"(\d+) dev".format(ADDRESS6)),
    NETMASK: re.compile(r"netmask\s+"
                        r"(?P<{}>\S+)".format(NETMASK)),
    NETMASK6: re.compile(r"post-up ip -6 addr add ([^/]+)/"
                         r"(?P<{}>\d+) dev".format(NETMASK6)),
    BROADCAST: re.compile(r"broadcast\s+"
                          r"(?P<{}>\S+)".format(BROADCAST)),
    GATEWAY: re.compile(r"gateway\s+"
                        r"(?P<{}>\S+)".format(GATEWAY)),
    GATEWAY6: re.compile(r"post-up ip -6 route add default via "
                         r"(?P<{}>.+) dev".format(GATEWAY6)),
    DNSNS: re.compile(r"dns-nameservers\s+(?P<{}>.+)".format(DNSNS))
}
IFACE_TEMPLATE = dict.fromkeys(FIELDS.keys())
# Map IPv6 availability by value index under `NetworkDetails`.
V6_PROXY = {
    ADDRESS: ADDRESS6,
    NETMASK: NETMASK6,
    GATEWAY: GATEWAY6,
    NAME: NAME,
    MAC: MAC,
}
DETAIL_PREPROCESS = {
    MAC: lambda value: value.upper(),
    DNSNS: lambda value: value.strip().split()
}


def _get_iface_blocks(data):
    """"Yield interface blocks as pairs of v4 and v6 halves."""
    lines, lines6 = [], []
    crt_lines = lines
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "iface" in line:
            if "inet6" in line:
                crt_lines = lines6
            if lines:
                yield lines, lines6
            lines[:] = []
            lines6[:] = []
            crt_lines = lines
        crt_lines.append(line)
    if lines:
        yield lines, lines6


def _get_field(line):
    for field, regex in FIELDS.items():
        match = regex.match(line)
        if match:
            yield field, match.group(field)


def _add_nic(iface, nics):
    if not iface or iface == IFACE_TEMPLATE:
        return    # no information gathered
    LOG.debug("Found new interface: %s", iface)
    # Each missing detail is marked as None.
    nic = network_model.NetworkDetails(**iface)
    nics.append(nic)


def parse(data):
    """Parse the received content and obtain network details."""
    if not data or not isinstance(data, six.string_types):
        LOG.error("Invalid Debian config to parse:\n%s", data)
        return

    LOG.info("Parsing Debian config...\n%s", data)
    nics = []    # list of NetworkDetails objects
    for lines_pair in _get_iface_blocks(data):
        iface = IFACE_TEMPLATE.copy()
        for lines, use_proxy in zip(lines_pair, (False, True)):
            for line in lines:
                for field, value in _get_field(line):
                    if use_proxy:
                        field = V6_PROXY.get(field)
                        if not field:
                            continue
                    func = DETAIL_PREPROCESS.get(field, lambda value: value)
                    iface[field] = func(value) if value != "None" else None
        _add_nic(iface, nics)

    return nics
