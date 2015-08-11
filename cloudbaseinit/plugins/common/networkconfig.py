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


import re

from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base as service_base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base as plugin_base
from cloudbaseinit.utils import network


LOG = oslo_logging.getLogger(__name__)

# Mandatory network details are marked with True. And
# if the key is a tuple, then at least one field must exists.
NET_REQUIRE = {
    ("name", "mac"): True,
    ("address", "address6"): True,
    ("netmask", "netmask6"): True,
    "broadcast": False,    # currently not used
    ("gateway", "gateway6"): False,
    "dnsnameservers": False
}


def _name2idx(name):
    """Get the position of a network interface by its name."""
    match = re.search(r"eth(\d+)", name, re.I)
    if not match:
        raise exception.CloudbaseInitException(
            "invalid NetworkDetails name {!r}"
            .format(name)
        )
    return int(match.group(1))


def _preprocess_nics(network_details, network_adapters):
    """Check NICs and fill missing data if possible."""
    # Initial checks.
    if not network_adapters:
        raise exception.CloudbaseInitException(
            "no network adapters available")
    # Sort VM adapters by name (assuming that those
    # from the context are in correct order).
    # Do this for a better matching by order
    # if hardware address is missing.
    network_adapters = sorted(network_adapters, key=lambda arg: arg[0])
    refined_network_details = []    # store here processed interfaces
    # Check and update every NetworkDetails object.
    total = len(network_adapters)
    for nic in network_details:
        if not isinstance(nic, service_base.NetworkDetails):
            raise exception.CloudbaseInitException(
                "invalid NetworkDetails object {!r}"
                .format(type(nic))
            )
        # Check requirements.
        final_status = True
        for fields, status in NET_REQUIRE.items():
            if not status:
                continue    # skip 'not required' entries
            if not isinstance(fields, tuple):
                fields = (fields,)
            final_status = any([getattr(nic, field) for field in fields])
            if not final_status:
                break
        address, netmask = nic.address, nic.netmask
        if final_status:
            # Additional check for info version.
            if not (address and netmask):
                final_status = nic.address6 and nic.netmask6
                if final_status:
                    address = address or network.address6_to_4_truncate(
                        nic.address6)
                    netmask = netmask or network.netmask6_to_4_truncate(
                        nic.netmask6)
        if not final_status:
            LOG.error("Incomplete NetworkDetails object %s", nic)
            continue
        # Complete hardware address if missing by selecting
        # the corresponding MAC in terms of naming, then ordering.
        if not nic.mac:
            # By name...
            macs = [adapter[1] for adapter in network_adapters
                    if adapter[0] == nic.name]
            mac = macs[0] if macs else None
            # ...or by order.
            idx = _name2idx(nic.name)
            if not mac and idx < total:
                mac = network_adapters[idx][1]
            nic = service_base.NetworkDetails(
                nic.name,
                mac,
                address,
                nic.address6,
                netmask,
                nic.netmask6,
                nic.broadcast,
                nic.gateway,
                nic.gateway6,
                nic.dnsnameservers
            )
        refined_network_details.append(nic)
    return refined_network_details


class NetworkConfigPlugin(plugin_base.BasePlugin):

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()
        network_details = service.get_network_details()
        if not network_details:
            return plugin_base.PLUGIN_EXECUTION_DONE, False

        # Check and save NICs by MAC.
        network_adapters = osutils.get_network_adapters()
        network_details = _preprocess_nics(network_details,
                                           network_adapters)
        macnics = {}
        for nic in network_details:
            # Assuming that the MAC address is unique.
            macnics[nic.mac] = nic

        # Try configuring all the available adapters.
        adapter_macs = [pair[1] for pair in network_adapters]
        reboot_required = False
        configured = False
        for mac in adapter_macs:
            nic = macnics.pop(mac, None)
            if not nic:
                LOG.warn("Missing details for adapter %s", mac)
                continue
            LOG.info("Configuring network adapter %s", mac)
            reboot = osutils.set_static_network_config(
                mac,
                nic.address,
                nic.netmask,
                nic.broadcast,
                nic.gateway,
                nic.dnsnameservers
            )
            reboot_required = reboot or reboot_required
            # Set v6 info too if available.
            if nic.address6 and nic.netmask6:
                osutils.set_static_network_config_v6(
                    mac,
                    nic.address6,
                    nic.netmask6,
                    nic.gateway6
                )
            configured = True
        for mac in macnics:
            LOG.warn("Details not used for adapter %s", mac)
        if not configured:
            LOG.error("No adapters were configured")

        return plugin_base.PLUGIN_EXECUTION_DONE, reboot_required
