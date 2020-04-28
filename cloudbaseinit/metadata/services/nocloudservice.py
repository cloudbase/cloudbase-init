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


class NoCloudConfigDriveService(baseconfigdrive.BaseConfigDriveService):

    def __init__(self):
        super(NoCloudConfigDriveService, self).__init__(
            'cidata', 'meta-data')
        self._meta_data = {}

    def get_user_data(self):
        return self._get_cache_data("user-data")

    def _get_meta_data(self):
        if self._meta_data:
            return self._meta_data

        raw_meta_data = self._get_cache_data("meta-data", decode=True)
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

        network_data_version = network_data.get("version")
        if network_data_version != 1:
            LOG.error("Network data version '%s' is not supported",
                      network_data_version)
            return

        network_config_parser = NoCloudNetworkConfigV1Parser()
        return network_config_parser.parse(network_data.get("config"))
