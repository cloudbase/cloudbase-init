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

import copy
import netaddr

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseconfigdrive
from cloudbaseinit.models import network as network_model
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import network as network_utils
from cloudbaseinit.utils import serialization


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class NoCloudNetworkConfigV1Parser(object):
    NETWORK_LINK_TYPE_PHY = 'physical'
    NETWORK_LINK_TYPE_BOND = 'bond'
    NETWORK_LINK_TYPE_VLAN = 'vlan'
    NETWORK_SERVICE_NAMESERVER = 'nameserver'

    SUPPORTED_NETWORK_CONFIG_TYPES = [
        NETWORK_LINK_TYPE_PHY,
        NETWORK_LINK_TYPE_BOND,
        NETWORK_LINK_TYPE_VLAN,
        NETWORK_SERVICE_NAMESERVER
    ]

    def _parse_subnets(self, subnets, link_name):
        networks = []

        if not subnets or not isinstance(subnets, list):
            LOG.warning("Subnets '%s' is empty or not a list.",
                        subnets)
            return networks

        for subnet in subnets:
            if not isinstance(subnet, dict):
                LOG.warning("Subnet '%s' is not a dictionary",
                            subnet)
                continue

            if subnet.get("type") in ["dhcp", "dhcp6"]:
                continue

            routes = []
            for route_data in subnet.get("routes", []):
                route_netmask = route_data.get("netmask")
                route_network = route_data.get("network")
                route_network_cidr = network_utils.ip_netmask_to_cidr(
                    route_network, route_netmask)

                route_gateway = route_data.get("gateway")
                route = network_model.Route(
                    network_cidr=route_network_cidr,
                    gateway=route_gateway
                )
                routes.append(route)

            address_cidr = subnet.get("address")
            netmask = subnet.get("netmask")
            if netmask:
                address_cidr = network_utils.ip_netmask_to_cidr(
                    address_cidr, netmask)

            gateway = subnet.get("gateway")
            if gateway:
                # Map the gateway as a default route, depending on the
                # IP family / version (4 or 6)
                gateway_net_cidr = "0.0.0.0/0"
                if netaddr.valid_ipv6(gateway):
                    gateway_net_cidr = "::/0"

                routes.append(
                    network_model.Route(
                        network_cidr=gateway_net_cidr,
                        gateway=gateway
                    )
                )

            networks.append(network_model.Network(
                link=link_name,
                address_cidr=address_cidr,
                dns_nameservers=subnet.get("dns_nameservers"),
                routes=routes
            ))

        return networks

    def _parse_physical_config_item(self, item):
        if not item.get('name'):
            LOG.warning("Physical NIC does not have a name.")
            return

        link = network_model.Link(
            id=item.get('name'),
            name=item.get('name'),
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address=item.get('mac_address'),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=None,
            vlan_id=None
        )

        return network_model.NetworkDetailsV2(
            links=[link],
            networks=self._parse_subnets(item.get("subnets"), link.name),
            services=[]
        )

    def _parse_bond_config_item(self, item):
        if not item.get('name'):
            LOG.warning("Bond does not have a name.")
            return

        bond_params = item.get('params')
        if not bond_params:
            LOG.warning("Bond does not have parameters")
            return

        bond_mode = bond_params.get('bond-mode')
        if bond_mode not in network_model.AVAILABLE_BOND_TYPES:
            raise exception.CloudbaseInitException(
                "Unsupported bond mode: %s" % bond_mode)

        bond_lacp_rate = None
        if bond_mode == network_model.BOND_TYPE_8023AD:
            bond_lacp_rate = bond_params.get('bond-lacp-rate')
            if (bond_lacp_rate and bond_lacp_rate not in
                    network_model.AVAILABLE_BOND_LACP_RATES):
                raise exception.CloudbaseInitException(
                    "Unsupported bond lacp rate: %s" % bond_lacp_rate)

        bond_xmit_hash_policy = bond_params.get('xmit_hash_policy')
        if (bond_xmit_hash_policy and bond_xmit_hash_policy not in
                network_model.AVAILABLE_BOND_LB_ALGORITHMS):
            raise exception.CloudbaseInitException(
                "Unsupported bond hash policy: %s" %
                bond_xmit_hash_policy)

        bond_interfaces = item.get('bond_interfaces')

        bond = network_model.Bond(
            members=bond_interfaces,
            type=bond_mode,
            lb_algorithm=bond_xmit_hash_policy,
            lacp_rate=bond_lacp_rate,
        )

        link = network_model.Link(
            id=item.get('name'),
            name=item.get('name'),
            type=network_model.LINK_TYPE_BOND,
            enabled=True,
            mac_address=item.get('mac_address'),
            mtu=item.get('mtu'),
            bond=bond,
            vlan_link=None,
            vlan_id=None
        )

        return network_model.NetworkDetailsV2(
            links=[link],
            networks=self._parse_subnets(item.get("subnets"), link.name),
            services=[]
        )

    def _parse_vlan_config_item(self, item):
        if not item.get('name'):
            LOG.warning("VLAN NIC does not have a name.")
            return

        link = network_model.Link(
            id=item.get('name'),
            name=item.get('name'),
            type=network_model.LINK_TYPE_VLAN,
            enabled=True,
            mac_address=item.get('mac_address'),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=item.get('vlan_link'),
            vlan_id=item.get('vlan_id')
        )

        return network_model.NetworkDetailsV2(
            links=[link],
            networks=self._parse_subnets(item.get("subnets"), link.name),
            services=[]
        )

    def _parse_nameserver_config_item(self, item):
        return network_model.NetworkDetailsV2(
            links=[],
            networks=[],
            services=[network_model.NameServerService(
                addresses=item.get('address', []),
                search=item.get('search')
            )]
        )

    def _get_network_config_parser(self, parser_type):
        parsers = {
            self.NETWORK_LINK_TYPE_PHY: self._parse_physical_config_item,
            self.NETWORK_LINK_TYPE_BOND: self._parse_bond_config_item,
            self.NETWORK_LINK_TYPE_VLAN: self._parse_vlan_config_item,
            self.NETWORK_SERVICE_NAMESERVER: self._parse_nameserver_config_item
        }
        parser = parsers.get(parser_type)
        if not parser:
            raise exception.CloudbaseInitException(
                "Network config parser '%s' does not exist",
                parser_type)
        return parser

    def parse(self, network_config):
        links = []
        networks = []
        services = []

        if network_config and network_config.get('network'):
            network_config = network_config.get('network')
        if network_config:
            network_config = network_config.get('config')

        if not network_config:
            LOG.warning("Network configuration is empty")
            return

        if not isinstance(network_config, list):
            LOG.warning("Network config '%s' is not a list.",
                        network_config)
            return

        for network_config_item in network_config:
            if not isinstance(network_config_item, dict):
                LOG.warning("Network config item '%s' is not a dictionary",
                            network_config_item)
                continue

            net_conf_type = network_config_item.get("type")
            if net_conf_type not in self.SUPPORTED_NETWORK_CONFIG_TYPES:
                LOG.warning("Network config type '%s' is not supported",
                            net_conf_type)
                continue

            net_details = (
                self._get_network_config_parser(net_conf_type)
                                               (network_config_item))

            if net_details:
                links += net_details.links
                networks += net_details.networks
                services += net_details.services

        return network_model.NetworkDetailsV2(
            links=links,
            networks=networks,
            services=services
        )


class NoCloudNetworkConfigV2Parser(object):
    DEFAULT_GATEWAY_CIDR_IPV4 = u"0.0.0.0/0"
    DEFAULT_GATEWAY_CIDR_IPV6 = u"::/0"

    NETWORK_LINK_TYPE_ETHERNET = 'ethernet'
    NETWORK_LINK_TYPE_BOND = 'bond'
    NETWORK_LINK_TYPE_VLAN = 'vlan'
    NETWORK_LINK_TYPE_BRIDGE = 'bridge'

    SUPPORTED_NETWORK_CONFIG_TYPES = {
        NETWORK_LINK_TYPE_ETHERNET: 'ethernets',
        NETWORK_LINK_TYPE_BOND: 'bonds',
        NETWORK_LINK_TYPE_VLAN: 'vlans',
    }

    def _parse_mac_address(self, item):
        return item.get("match", {}).get("macaddress")

    def _parse_addresses(self, item, link_name):
        networks = []
        services = []

        routes = []
        # handle route config in deprecated gateway4/gateway6
        gateway4 = item.get("gateway4")
        gateway6 = item.get("gateway6")
        default_route = None
        if gateway6 and netaddr.valid_ipv6(gateway6):
            default_route = network_model.Route(
                network_cidr=self.DEFAULT_GATEWAY_CIDR_IPV6,
                gateway=gateway6)
        elif gateway4 and netaddr.valid_ipv4(gateway4):
            default_route = network_model.Route(
                network_cidr=self.DEFAULT_GATEWAY_CIDR_IPV4,
                gateway=gateway4)
        if default_route:
            routes.append(default_route)

        # netplan format config
        routes_config = item.get("routes", {})
        for route_config in routes_config:
            network_cidr = route_config.get("to")
            gateway = route_config.get("via")
            if network_cidr.lower() == "default":
                if netaddr.valid_ipv6(gateway):
                    network_cidr = self.DEFAULT_GATEWAY_CIDR_IPV6
                else:
                    network_cidr = self.DEFAULT_GATEWAY_CIDR_IPV4
            route = network_model.Route(
                network_cidr=network_cidr,
                gateway=gateway)
            routes.append(route)

        nameservers = item.get("nameservers")
        nameserver_addresses = nameservers.get("addresses", []) \
            if nameservers else []
        searches = nameservers.get("search", [])
        service = network_model.NameServerService(
            addresses=nameserver_addresses,
            search=','.join(searches) if searches else None,
        )
        services.append(service)

        addresses = item.get("addresses", [])
        for addr in addresses:
            network = network_model.Network(
                link=link_name,
                address_cidr=addr,
                dns_nameservers=nameserver_addresses,
                routes=routes
            )
            networks.append(network)

        return networks, services

    def _parse_ethernet_config_item(self, item):
        if not item.get('name'):
            LOG.warning("Ethernet does not have a name.")
            return

        name = item.get('name')
        eth_name = item.get("set-name", name)
        link = network_model.Link(
            id=name,
            name=eth_name,
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address=self._parse_mac_address(item),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=None,
            vlan_id=None
        )

        networks, services = self._parse_addresses(item, link.name)
        return network_model.NetworkDetailsV2(
            links=[link],
            networks=networks,
            services=services,
        )

    def _parse_bond_config_item(self, item):
        if not item.get('name'):
            LOG.warning("Bond does not have a name.")
            return

        bond_params = item.get('parameters')
        if not bond_params:
            LOG.warning("Bond does not have parameters")
            return

        bond_mode = bond_params.get('mode')
        if bond_mode not in network_model.AVAILABLE_BOND_TYPES:
            raise exception.CloudbaseInitException(
                "Unsupported bond mode: %s" % bond_mode)

        bond_lacp_rate = None
        if bond_mode == network_model.BOND_TYPE_8023AD:
            bond_lacp_rate = bond_params.get('lacp-rate')
            if (bond_lacp_rate and bond_lacp_rate not in
                    network_model.AVAILABLE_BOND_LACP_RATES):
                raise exception.CloudbaseInitException(
                    "Unsupported bond lacp rate: %s" % bond_lacp_rate)

        bond_xmit_hash_policy = bond_params.get('transmit-hash-policy')
        if (bond_xmit_hash_policy and bond_xmit_hash_policy not in
                network_model.AVAILABLE_BOND_LB_ALGORITHMS):
            raise exception.CloudbaseInitException(
                "Unsupported bond hash policy: %s" %
                bond_xmit_hash_policy)

        bond_interfaces = item.get('interfaces')

        bond = network_model.Bond(
            members=bond_interfaces,
            type=bond_mode,
            lb_algorithm=bond_xmit_hash_policy,
            lacp_rate=bond_lacp_rate,
        )

        link = network_model.Link(
            id=item.get('name'),
            name=item.get('name'),
            type=network_model.LINK_TYPE_BOND,
            enabled=True,
            mac_address=self._parse_mac_address(item),
            mtu=item.get('mtu'),
            bond=bond,
            vlan_link=None,
            vlan_id=None
        )

        networks, services = self._parse_addresses(item, link.name)
        return network_model.NetworkDetailsV2(
            links=[link],
            networks=networks,
            services=services
        )

    def _parse_vlan_config_item(self, item):
        if not item.get('name'):
            LOG.warning("VLAN NIC does not have a name.")
            return

        link = network_model.Link(
            id=item.get('name'),
            name=item.get('name'),
            type=network_model.LINK_TYPE_VLAN,
            enabled=True,
            mac_address=self._parse_mac_address(item),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=item.get('link'),
            vlan_id=item.get('id')
        )

        networks, services = self._parse_addresses(item, link.name)
        return network_model.NetworkDetailsV2(
            links=[link],
            networks=networks,
            services=services,
        )

    def _get_network_config_parser(self, parser_type):
        parsers = {
            self.NETWORK_LINK_TYPE_ETHERNET: self._parse_ethernet_config_item,
            self.NETWORK_LINK_TYPE_BOND: self._parse_bond_config_item,
            self.NETWORK_LINK_TYPE_VLAN: self._parse_vlan_config_item,
        }
        parser = parsers.get(parser_type)
        if not parser:
            raise exception.CloudbaseInitException(
                "Network config parser '%s' does not exist",
                parser_type)
        return parser

    def parse(self, network_config):
        links = []
        networks = []
        services = []

        if network_config and network_config.get('network'):
            network_config = network_config.get('network')

        if not network_config:
            LOG.warning("Network configuration is empty")
            return

        if not isinstance(network_config, dict):
            LOG.warning("Network config '%s' is not a dict.",
                        network_config)
            return

        for singular, plural in self.SUPPORTED_NETWORK_CONFIG_TYPES.items():
            network_config_items = network_config.get(plural, {})
            if not network_config_items:
                continue

            if not isinstance(network_config_items, dict):
                LOG.warning("Network config '%s' is not a dict",
                            network_config_items)
                continue

            for name, network_config_item in network_config_items.items():
                if not isinstance(network_config_item, dict):
                    LOG.warning(
                        "network config item '%s' of type %s is not a dict",
                        network_config_item, singular)
                    continue

                item = copy.deepcopy(network_config_item)
                item['name'] = name
                net_details = (
                    self._get_network_config_parser(singular)
                    (item))

                if net_details:
                    links += net_details.links
                    networks += net_details.networks
                    services += net_details.services

        return network_model.NetworkDetailsV2(
            links=links,
            networks=networks,
            services=services
        )


class NoCloudNetworkConfigParser(object):

    @staticmethod
    def parse(network_data):
        # we can have a network key in some cases
        if network_data.get("network"):
            network_data = network_data.get("network")
        network_data_version = network_data.get("version")

        if network_data_version == 1:
            network_config_parser = NoCloudNetworkConfigV1Parser()
        elif network_data_version == 2:
            network_config_parser = NoCloudNetworkConfigV2Parser()
        else:
            raise exception.CloudbaseInitException(
                "Unsupported network_data_version: '%s'"
                % network_data_version)

        return network_config_parser.parse(network_data)


class NoCloudConfigDriveService(baseconfigdrive.BaseConfigDriveService):

    def __init__(self):
        super(NoCloudConfigDriveService, self).__init__(
            'cidata', CONF.nocloud.metadata_file,
            CONF.nocloud.userdata_file)
        self._meta_data = {}

    def get_user_data(self):
        return self._get_cache_data(self._userdata_file)

    def _get_meta_data(self):
        if self._meta_data:
            return self._meta_data

        raw_meta_data = self._get_cache_data(
            self._metadata_file, decode=True)
        try:
            self._meta_data = (
                serialization.parse_json_yaml(raw_meta_data))
        except serialization.YamlParserConfigError as ex:
            LOG.error("Metadata could not be parsed")
            LOG.exception(ex)

        return self._meta_data

    def get_host_name(self):
        return self._get_meta_data().get('local-hostname')

    def get_instance_id(self):
        return self._get_meta_data().get('instance-id')

    def get_public_keys(self):
        raw_ssh_keys = self._get_meta_data().get('public-keys')
        if not raw_ssh_keys:
            return []

        if isinstance(raw_ssh_keys, list):
            return raw_ssh_keys

        return [raw_ssh_keys[key].get('openssh-key') for key in raw_ssh_keys]

    def get_network_details(self):
        debian_net_config = self._get_meta_data().get('network-interfaces')
        if not debian_net_config:
            return None

        return debiface.parse(debian_net_config)

    def get_network_details_v2(self):
        try:
            raw_network_data = self._get_cache_data("network-config",
                                                    decode=True)
            network_data = serialization.parse_json_yaml(raw_network_data)
            if not network_data:
                LOG.info("V2 network metadata is empty")
                return
            if not isinstance(network_data, dict):
                LOG.warning("V2 network metadata is not a dictionary")
                return
        except base.NotExistingMetadataException:
            LOG.info("V2 network metadata not found")
            return
        except serialization.YamlParserConfigError:
            LOG.exception("V2 network metadata could not be deserialized")
            return

        return NoCloudNetworkConfigParser.parse(network_data)
