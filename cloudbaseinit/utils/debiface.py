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

import six

from cloudbaseinit.metadata.services import base as service_base
from cloudbaseinit.openstack.common import log as logging


LOG = logging.getLogger(__name__)

NAME = "name"
MAC = "mac"
ADDRESS = "address"
NETMASK = "netmask"
BROADCAST = "broadcast"
GATEWAY = "gateway"
DNSNS = "dnsnameservers"
# fields of interest (order and regexp)
FIELDS = {
    NAME: (0, re.compile(r"iface\s+(?P<{}>\S+)"
                         r"\s+inet\s+static".format(NAME))),
    MAC: (1, re.compile(r"hwaddress\s+ether\s+"
                        r"(?P<{}>\S+)".format(MAC))),
    ADDRESS: (2, re.compile(r"address\s+"
                            r"(?P<{}>\S+)".format(ADDRESS))),
    NETMASK: (3, re.compile(r"netmask\s+"
                            r"(?P<{}>\S+)".format(NETMASK))),
    BROADCAST: (4, re.compile(r"broadcast\s+"
                              r"(?P<{}>\S+)".format(BROADCAST))),
    GATEWAY: (5, re.compile(r"gateway\s+"
                            r"(?P<{}>\S+)".format(GATEWAY))),
    DNSNS: (6, re.compile(r"dns-nameservers\s+(?P<{}>.+)".format(DNSNS)))
}
IFACE_TEMPLATE = dict.fromkeys(range(len(FIELDS)))


def _get_field(line):
    for field, (index, regex) in FIELDS.items():
        match = regex.match(line)
        if match:
            return index, match.group(field)


def _add_nic(iface, nics):
    if not iface:
        return
    details = [iface[key] for key in sorted(iface)]
    LOG.debug("Found new interface: %s", details)
    # each missing detail is marked as None
    nic = service_base.NetworkDetails(*details)
    nics.append(nic)


def parse(data):
    """Parse the received content and obtain network details."""
    # TODO(cpoieana): support IPv6 flavors
    if not data or not isinstance(data, six.string_types):
        LOG.error("Invalid debian config to parse:\n%s", data)
        return
    LOG.info("Parsing debian config...\n%s", data)
    nics = []    # list of NetworkDetails objects
    iface = {}
    # take each line and process it
    for line in data.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ret = _get_field(line)
        if not ret:
            continue
        # save the detail
        index = ret[0]
        if index == 0:
            # we found a new interface
            _add_nic(iface, nics)
            iface = IFACE_TEMPLATE.copy()
        value = ret[1]
        if index == 1:
            value = value.upper()
        elif index == 6:
            value = value.strip().split()
        iface[index] = value
    # also add the last one
    _add_nic(iface, nics)
    return nics
