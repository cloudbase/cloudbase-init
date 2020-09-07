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

# pylint: disable=missing-docstring, bad-builtin


import os
import re
import socket
import struct

from oslo_log import log as oslo_logging
import six

from cloudbaseinit.metadata.services import base
from cloudbaseinit.models import network as network_model
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import encoding


LOG = oslo_logging.getLogger(__name__)

CONTEXT_FILE = "context.sh"
INSTANCE_ID = "iid-dsopennebula"
# interface name default template
IF_FORMAT = "eth{iid}"

# metadata identifiers
HOST_NAME = ["SET_HOSTNAME", "HOSTNAME"]
USER_DATA = ["USER_DATA", "USERDATA"]
PUBLIC_KEY = ["SSH_PUBLIC_KEY", "SSH_KEY"]

MAC = ["ETH{iid}_MAC"]
ADDRESS = ["ETH{iid}_IP"]
NETMASK = ["ETH{iid}_MASK"]
GATEWAY = ["ETH{iid}_GATEWAY"]
DNSNS = ["ETH{iid}_DNS"]


class OpenNebulaService(base.BaseMetadataService):

    """Service handling ONE.

    Service able to expose OpenNebula metadata
    using information found in a mounted ISO file.
    """

    def __init__(self):
        super(OpenNebulaService, self).__init__()
        self._context_path = None
        self._raw_content = None
        self._dict_content = {}

    def _nic_count(self):
        """Return the number of available interfaces."""
        mac = MAC[0]
        iid = 0
        while self._dict_content.get(mac.format(iid=iid)):
            iid += 1
        return iid

    @staticmethod
    def _parse_shell_variables(content):
        """Returns a dictionary with variables and their values.

        This is a dummy approach, because it works only with simple literals.
        """
        # preprocess the content
        lines = []
        for line in content.splitlines():
            if not line or line.startswith(b"#"):
                continue
            lines.append(line)
        # for cleaner pattern matching
        lines.append(b"__REGEX_DUMMY__='__regex_dummy__'")
        sep = b"\r\n" if b"\r\n" in content else b"\n"
        new_content = sep.join(lines)
        # get pairs
        pairs = {}
        pattern = (br"(?P<key>\w+)=((?P<int_value>\d+)|"
                   br"['\"](?P<str_value>[\s\S]*?)['\"])(?=\s+\w+=)")
        for match in re.finditer(pattern, new_content):
            key = encoding.get_as_string(match.group("key"))
            val = match.group("str_value")
            if match.group("int_value"):
                val = int(match.group("int_value"))
            pairs[key] = val
        return pairs

    @staticmethod
    def _calculate_netmask(address, gateway):
        """Try to determine a default netmask.

        It is a simple, frequent and dummy prediction
        based on the provided IP and gateway addresses.
        """
        address_chunks = address.split(".")
        gateway_chunks = gateway.split(".")
        netmask_chunks = []
        for achunk, gchunk in six.moves.zip(
                address_chunks, gateway_chunks):
            if achunk == gchunk:
                nchunk = "255"
            else:
                nchunk = "0"
            netmask_chunks.append(nchunk)
        return ".".join(netmask_chunks)

    @staticmethod
    def _compute_broadcast(address, netmask):
        address_ulong, = struct.unpack("!L", socket.inet_aton(address))
        netmask_ulong, = struct.unpack("!L", socket.inet_aton(netmask))
        bitmask = 0xFFFFFFFF
        broadcast_ulong = address_ulong | ~netmask_ulong & bitmask
        broadcast = socket.inet_ntoa(struct.pack("!L", broadcast_ulong))
        return broadcast

    def _parse_context(self):
        # Get the content if it's not already retrieved and parse it.
        if not self._raw_content:
            if not self._context_path:
                msg = "No metadata file path found"
                LOG.debug(msg)
                raise base.NotExistingMetadataException(msg)
            with open(self._context_path, "rb") as fin:
                self._raw_content = fin.read()
            # fill the dict with values
            vardict = OpenNebulaService._parse_shell_variables(
                self._raw_content
            )
            self._dict_content.update(vardict)

    def _get_data(self, name):
        # Return the requested field's value or raise an error if not found.
        if name not in self._dict_content:
            msg = "Metadata {} not found".format(name)
            LOG.debug(msg)
            raise base.NotExistingMetadataException(msg)
        return self._dict_content[name]

    def _get_cache_data(self, names, iid=None, decode=False):
        # Solves caching issues when working with
        # multiple names (lists not hashable).
        # This happens because the caching function used
        # to store already computed results inside a dictionary
        # and the keys were strings (and must be anything that
        # is hashable under a dictionary, that's why the exception
        # is thrown).
        names = names[:]
        if iid is not None:
            for ind, value in enumerate(names):
                names[ind] = value.format(iid=iid)
        for name in names:
            try:
                return super(OpenNebulaService, self)._get_cache_data(
                    name, decode=decode)
            except base.NotExistingMetadataException:
                pass
        msg = "None of {} metadata was found".format(", ".join(names))
        LOG.debug(msg)
        raise base.NotExistingMetadataException(msg)

    def load(self):
        """Loads the context metadata from the ISO provided by OpenNebula."""
        super(OpenNebulaService, self).__init__()
        LOG.debug("Searching for a drive containing OpenNebula context data")
        osutils = osutils_factory.get_os_utils()
        for drive in osutils.get_cdrom_drives():
            label = osutils.get_volume_label(drive)
            file_path = os.path.join(drive, CONTEXT_FILE)
            if os.path.isfile(file_path):
                LOG.info("Found drive %(label)s (%(drive)s) with "
                         "OpenNebula metadata file %(file_path)s",
                         {"label": label, "drive": drive,
                          "file_path": file_path})
                self._context_path = file_path
                # Load and parse the file on-site.
                self._parse_context()
                return True
        LOG.error("No drive or context file found")
        return False

    def get_instance_id(self):
        # return a dummy default value
        return INSTANCE_ID

    def get_host_name(self):
        return self._get_cache_data(HOST_NAME, decode=True)

    def get_user_data(self):
        return self._get_cache_data(USER_DATA)

    def get_public_keys(self):
        return self._get_cache_data(PUBLIC_KEY, decode=True).splitlines()

    def get_network_details(self):
        """Return a list of NetworkDetails objects.

        With each object from that list, the corresponding
        NIC (by mac) can be statically configured.
        If no such object is present, then is believed that
        this is handled by DHCP (user didn't provide sufficient data).
        """
        network_details = []
        ncount = self._nic_count()
        # for every interface
        for iid in range(ncount):
            try:
                # get existing values
                mac = self._get_cache_data(MAC, iid=iid, decode=True).upper()
                address = self._get_cache_data(ADDRESS, iid=iid, decode=True)
                # try to find/predict and compute the rest
                try:
                    gateway = self._get_cache_data(GATEWAY, iid=iid,
                                                   decode=True)
                except base.NotExistingMetadataException:
                    gateway = None
                try:
                    netmask = self._get_cache_data(NETMASK, iid=iid,
                                                   decode=True)
                except base.NotExistingMetadataException:
                    if not gateway:
                        raise
                    netmask = self._calculate_netmask(address, gateway)
                broadcast = self._compute_broadcast(address, netmask)
                # gather them as namedtuple objects
                details = network_model.NetworkDetails(
                    name=IF_FORMAT.format(iid=iid),
                    mac=mac,
                    address=address,
                    address6=None,
                    netmask=netmask,
                    netmask6=None,
                    broadcast=broadcast,
                    gateway=gateway,
                    gateway6=None,
                    dnsnameservers=self._get_cache_data(
                        DNSNS, iid=iid, decode=True).split(" ")
                )
            except base.NotExistingMetadataException:
                LOG.debug("Incomplete NIC details")
            else:
                network_details.append(details)
        return network_details
