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

import netaddr
from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.models import network as network_model
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base as plugin_base
from cloudbaseinit.utils import network


LOG = oslo_logging.getLogger(__name__)

# Mandatory network details are marked with True. And
# if the key is a tuple, then at least one field must exist.
NET_REQUIRE = {
    ("name", "mac"): True,
    ("address", "address6"): True,
    ("netmask", "netmask6"): True,
    "broadcast": False,    # currently not used
    ("gateway", "gateway6"): False,
    "dnsnameservers": False
}

BOND_FORMAT_STR = "bond_%s"


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
        if not isinstance(nic, network_model.NetworkDetails):
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
            nic = network_model.NetworkDetails(
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
    def _process_network_details(self, network_details):
        osutils = osutils_factory.get_os_utils()
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

            name = osutils.get_network_adapter_name_by_mac_address(mac)
            LOG.info("Configuring network adapter: %s", name)

            # In v6 only case, nic.address and nic.netmask could be unset
            if nic.address and nic.netmask:
                reboot = osutils.set_static_network_config(
                    name,
                    nic.address,
                    nic.netmask,
                    nic.gateway,
                    nic.dnsnameservers or []
                )
            reboot_required = reboot or reboot_required
            # Set v6 info too if available.
            if nic.address6 and nic.netmask6:
                reboot = osutils.set_static_network_config(
                    name,
                    nic.address6,
                    nic.netmask6,
                    nic.gateway6,
                    []
                )
            reboot_required = reboot or reboot_required
            configured = True
        for mac in macnics:
            LOG.warn("Details not used for adapter %s", mac)
        if not configured:
            LOG.error("No adapters were configured")

        return plugin_base.PLUGIN_EXECUTION_DONE, reboot_required

    @staticmethod
    def _process_link_common(osutils, link):
        if link.mtu:
            LOG.debug(
                "Setting MTU on network adapter \"%(name)s\": %(mtu)s",
                {"name": link.name, "mtu": link.mtu})
            osutils.set_network_adapter_mtu(link.name, link.mtu)

        LOG.debug(
            "Enable network adapter \"%(name)s\": %(enabled)s",
            {"name": link.name, "enabled": link.enabled})
        osutils.enable_network_adapter(link.name, link.enabled)

    @staticmethod
    def _process_physical_links(osutils, network_details):
        physical_links = [
            link for link in network_details.links if
            link.type == network_model.LINK_TYPE_PHYSICAL]

        for link in physical_links:
            adapter_name = osutils.get_network_adapter_name_by_mac_address(
                link.mac_address)

            if adapter_name != link.name:
                LOG.info(
                    "Renaming network adapter \"%(old_name)s\" to "
                    "\"%(new_name)s\"",
                    {"old_name": adapter_name, "new_name": link.name})
                osutils.rename_network_adapter(adapter_name, link.name)

            NetworkConfigPlugin._process_link_common(osutils, link)

    @staticmethod
    def _process_bond_links(osutils, network_details):
        bond_links = [
            link for link in network_details.links if
            link.type == network_model.LINK_TYPE_BOND]

        for link in bond_links:
            bond_name = BOND_FORMAT_STR % link.id
            primary_nic_vlan_id = None
            LOG.info("Creating network team: %s", bond_name)
            osutils.create_network_team(
                bond_name, link.bond.type, link.bond.lb_algorithm,
                link.bond.members, link.mac_address, link.name,
                primary_nic_vlan_id, link.bond.lacp_rate)

            NetworkConfigPlugin._process_link_common(osutils, link)

    @staticmethod
    def _process_vlan_links(osutils, network_details):
        vlan_links = [
            link for link in network_details.links if
            link.type == network_model.LINK_TYPE_VLAN]

        for link in vlan_links:
            bond_name = BOND_FORMAT_STR % link.vlan_link
            LOG.info(
                "Creating bond network adapter \"%(nic_name)s\" on team "
                "\"%(bond_name)s\" with VLAN: %(vlan_id)s",
                {"nic_name": link.name, "bond_name": bond_name,
                 "vlan_id": link.vlan_id})
            osutils.add_network_team_nic(bond_name, link.name, link.vlan_id)

            NetworkConfigPlugin._process_link_common(osutils, link)

    @staticmethod
    def _get_default_dns_nameservers(network_details):
        ipv4_nameservers = []
        ipv6_nameservers = []
        for s in network_details.services:
            if isinstance(s, network_model.NameServerService):
                for nameserver in s.addresses:
                    if netaddr.valid_ipv6(nameserver):
                        ipv6_nameservers.append(nameserver)
                    else:
                        ipv4_nameservers.append(nameserver)
        return (ipv4_nameservers, ipv6_nameservers)

    @staticmethod
    def _process_networks(osutils, network_details):
        reboot_required = False
        ipv4_ns, ipv6_ns = NetworkConfigPlugin._get_default_dns_nameservers(
            network_details)

        for net in network_details.networks:
            ip_address, prefix_len = net.address_cidr.split("/")

            gateway = None
            default_gw_route = [
                r for r in net.routes if
                netaddr.IPNetwork(r.network_cidr).prefixlen == 0]
            if default_gw_route:
                gateway = default_gw_route[0].gateway

            nameservers = net.dns_nameservers
            if not nameservers:
                if netaddr.valid_ipv6(ip_address):
                    nameservers = ipv6_ns
                else:
                    nameservers = ipv4_ns

            LOG.info(
                "Setting static IP configuration on network adapter "
                "\"%(name)s\". IP: %(ip)s, prefix length: %(prefix_len)s, "
                "gateway: %(gateway)s, dns: %(dns)s",
                {"name": net.link, "ip": ip_address, "prefix_len": prefix_len,
                 "gateway": gateway, "dns": nameservers})
            reboot = osutils.set_static_network_config(
                net.link, ip_address, prefix_len, gateway, nameservers)
            reboot_required = reboot or reboot_required

        return reboot_required

    @staticmethod
    def _process_network_details_v2(network_details):
        osutils = osutils_factory.get_os_utils()

        NetworkConfigPlugin._process_physical_links(
            osutils, network_details)
        NetworkConfigPlugin._process_bond_links(osutils, network_details)
        NetworkConfigPlugin._process_vlan_links(osutils, network_details)
        reboot_required = NetworkConfigPlugin._process_networks(
            osutils, network_details)

        return plugin_base.PLUGIN_EXECUTION_DONE, reboot_required

    def execute(self, service, shared_data):
        network_details = service.get_network_details_v2()
        if network_details:
            return self._process_network_details_v2(network_details)

        network_details = service.get_network_details()
        if network_details:
            return self._process_network_details(network_details)

        return plugin_base.PLUGIN_EXECUTION_DONE, False
