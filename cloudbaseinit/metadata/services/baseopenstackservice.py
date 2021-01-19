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


import json
import posixpath

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.models import network as network_model
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import network as network_utils
from cloudbaseinit.utils import x509constants

NETWORK_LINK_TYPE_PHYSICAL = "phy"
NETWORK_LINK_TYPE_BOND = "bond"
NETWORK_LINK_TYPE_VLAN = "vlan"

NETWORK_TYPE_IPV4 = "ipv4"
NETWORK_TYPE_IPV4_DHCP = "ipv4_dhcp"
NETWORK_TYPE_IPV6 = "ipv6"
NETWORK_TYPE_IPV6_DHCP = "ipv6_dhcp"

NETWORK_SERVICE_TYPE_DNS = "dns"

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class BaseOpenStackService(base.BaseMetadataService):

    def get_content(self, name):
        path = posixpath.normpath(
            posixpath.join('openstack', 'content', name))
        return self._get_cache_data(path)

    def get_user_data(self):
        path = posixpath.normpath(
            posixpath.join('openstack', 'latest', 'user_data'))
        return self._get_cache_data(path)

    def _get_openstack_json_data(self, version, file_name):
        path = posixpath.normpath(
            posixpath.join('openstack', version, file_name))
        data = self._get_cache_data(path, decode=True)
        if data:
            return json.loads(data)

    def _get_meta_data(self, version='latest'):
        return self._get_openstack_json_data(version, 'meta_data.json')

    def _get_network_data(self, version='latest'):
        return self._get_openstack_json_data(version, 'network_data.json')

    def get_instance_id(self):
        return self._get_meta_data().get('uuid')

    def get_host_name(self):
        return self._get_meta_data().get('hostname')

    def get_public_keys(self):
        """Get a list of all unique public keys found among the metadata."""
        public_keys = []
        meta_data = self._get_meta_data()
        public_keys_dict = meta_data.get("public_keys")
        if public_keys_dict:
            public_keys = list(public_keys_dict.values())
        keys = meta_data.get("keys")
        if keys:
            for key_dict in keys:
                if key_dict["type"] == "ssh":
                    public_keys.append(key_dict["data"])
        return list(set((key.strip() for key in public_keys)))

    def get_network_details(self):
        network_config = self._get_meta_data().get('network_config')
        if not network_config:
            return None
        key = "content_path"
        if key not in network_config:
            return None

        content_name = network_config[key].rsplit("/", 1)[-1]
        content = self.get_content(content_name)
        content = encoding.get_as_string(content)

        return debiface.parse(content)

    @staticmethod
    def _parse_network_data_links(links_data):
        links = []
        for link_data in links_data:
            link_id = link_data.get("id")
            mac = link_data.get("ethernet_mac_address")
            mtu = link_data.get("mtu")
            openstack_link_type = link_data.get("type")

            bond = None
            vlan_id = None
            vlan_link = None
            if openstack_link_type == NETWORK_LINK_TYPE_BOND:
                link_type = network_model.LINK_TYPE_BOND
                bond_links = link_data.get("bond_links")
                bond_mode = link_data.get("bond_mode")
                bond_xmit_hash_policy = link_data.get("bond_xmit_hash_policy")

                if bond_mode not in network_model.AVAILABLE_BOND_TYPES:
                    raise exception.CloudbaseInitException(
                        "Unsupported bond mode: %s" % bond_mode)

                if (bond_xmit_hash_policy is not None and
                        bond_xmit_hash_policy not in
                        network_model.AVAILABLE_BOND_LB_ALGORITHMS):
                    raise exception.CloudbaseInitException(
                        "Unsupported bond hash policy: %s" %
                        bond_xmit_hash_policy)

                bond = network_model.Bond(
                    members=bond_links,
                    type=bond_mode,
                    lb_algorithm=bond_xmit_hash_policy,
                    lacp_rate=None,
                )
            elif openstack_link_type == NETWORK_LINK_TYPE_VLAN:
                link_type = network_model.LINK_TYPE_VLAN
                vlan_id = link_data.get("vlan_id")
                vlan_link = link_data.get("vlan_link")
                vlan_mac_address = link_data.get("vlan_mac_address")
                if vlan_mac_address is not None:
                    mac = vlan_mac_address
            else:
                # Any other link type is considered physical
                link_type = network_model.LINK_TYPE_PHYSICAL

            link = network_model.Link(
                id=link_id,
                name=link_id,
                type=link_type,
                enabled=True,
                mac_address=mac,
                mtu=mtu,
                bond=bond,
                vlan_id=vlan_id,
                vlan_link=vlan_link)
            links.append(link)

        return links

    @staticmethod
    def _parse_dns_data(services_data):
        dns_nameservers = []
        for service_data in services_data:
            service_type = service_data.get("type")
            if service_type != NETWORK_SERVICE_TYPE_DNS:
                LOG.warn("Skipping unsupported service type: %s", service_type)
                continue

            address = service_data.get("address")
            if address is not None:
                dns_nameservers.append(address)

        return dns_nameservers

    @staticmethod
    def _parse_network_data_networks(networks_data):
        networks = []
        for network_data in networks_data:
            network_type = network_data.get("type")
            if network_type not in [NETWORK_TYPE_IPV4, NETWORK_TYPE_IPV6]:
                continue

            link_id = network_data.get("link")
            ip_address = network_data.get("ip_address")
            netmask = network_data.get("netmask")
            address_cidr = network_utils.ip_netmask_to_cidr(
                ip_address, netmask)

            routes = []
            for route_data in network_data.get("routes", []):
                gateway = route_data.get("gateway")
                network = route_data.get("network")
                netmask = route_data.get("netmask")
                network_cidr = network_utils.ip_netmask_to_cidr(
                    network, netmask)

                route = network_model.Route(
                    network_cidr=network_cidr,
                    gateway=gateway
                )
                routes.append(route)

            dns_nameservers = BaseOpenStackService._parse_dns_data(
                network_data.get("services", []))

            network = network_model.Network(
                link=link_id,
                address_cidr=address_cidr,
                dns_nameservers=dns_nameservers,
                routes=routes
            )
            networks.append(network)

        return networks

    @staticmethod
    def _parse_network_data_services(services_data):
        services = []
        dns_nameservers = BaseOpenStackService._parse_dns_data(services_data)
        if len(dns_nameservers):
            service = network_model.NameServerService(
                addresses=dns_nameservers,
                search=None
            )
            services.append(service)
        return services

    def get_network_details_v2(self):
        try:
            network_data = self._get_network_data()
        except base.NotExistingMetadataException:
            LOG.info("V2 network metadata not found")
            return

        links = self._parse_network_data_links(
            network_data.get("links", []))
        networks = self._parse_network_data_networks(
            network_data.get("networks", []))
        services = self._parse_network_data_services(
            network_data.get("services", []))

        return network_model.NetworkDetailsV2(
            links=links,
            networks=networks,
            services=services
        )

    def get_admin_username(self):
        return self._get_meta_data().get('meta', {}).get('admin_username')

    def get_admin_password(self):
        meta_data = self._get_meta_data()
        meta = meta_data.get('meta')

        if meta and 'admin_pass' in meta:
            password = meta['admin_pass']
        elif 'admin_pass' in meta_data:
            password = meta_data['admin_pass']
        else:
            password = None

        return password

    def get_client_auth_certs(self):
        """Gather all unique certificates found among the metadata.

        If there are no certificates under "meta" or "keys" field,
        then try looking into user-data for this kind of information.
        """
        certs = []
        meta_data = self._get_meta_data()

        meta = meta_data.get("meta")
        if meta:
            cert_data_list = []
            idx = 0
            while True:
                # Chunking is necessary as metadata items can be
                # max. 255 chars long.
                cert_chunk = meta.get("admin_cert%d" % idx)
                if not cert_chunk:
                    break
                cert_data_list.append(cert_chunk)
                idx += 1
            if cert_data_list:
                # It's a list of strings for sure.
                certs.append("".join(cert_data_list))

        keys = meta_data.get("keys")
        if keys:
            for key_dict in keys:
                if key_dict["type"] == "x509":
                    certs.append(key_dict["data"])

        if not certs:
            # Look if the user_data contains a PEM certificate
            try:
                user_data = self.get_user_data().strip()
                if user_data.startswith(
                        x509constants.PEM_HEADER.encode()):
                    certs.append(encoding.get_as_string(user_data))
            except base.NotExistingMetadataException:
                LOG.debug("user_data metadata not present")

        return list(set((cert.strip() for cert in certs)))
