# Copyright 2020 Alexander Birkner
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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.models import network as network_model
from cloudbaseinit.utils import network as network_utils
from oslo_log import log as oslo_logging
from requests import RequestException

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class HiBeeService(base.BaseHTTPMetadataService):
    """Metadata Service for HiBee."""
    def __init__(self):
        super(HiBeeService, self).__init__(
            base_url=CONF.hibee.metadata_base_url)

        self._enable_retry = True

    def load(self):
        """Load all the available information from the metadata service."""
        super(HiBeeService, self).load()

        if not CONF.hibee.metadata_base_url:
            LOG.debug('HiBee metadata url not set')
        else:
            try:
                # Try to fetch the metadata from service
                self._get_meta_data()
                return True
            except Exception as ex:
                LOG.exception(ex)
                LOG.debug('Metadata not found at URL \'%s\'' %
                          CONF.hibee.metadata_base_url)
        return False

    def get_instance_id(self):
        """Get the identifier for the current installation."""
        return self._get_meta_data().get("id")

    def get_admin_password(self):
        """Get the admin password from the metadata service.

        Note:
            The password is deleted from the Backend after the first
            call of this method.
        """
        password = None
        for _ in range(CONF.retry_count):
            try:
                metadata_url = "%s/password" % CONF.hibee.metadata_base_url
                password = self._get_data(metadata_url).strip()
            except RequestException as exc:
                LOG.debug("Requesting the password failed: %s",
                          exc.response.status_code)
                continue
            except Exception:
                LOG.error("Failed to request the password for unknown reason.")
                continue

            if not password:
                LOG.warning("There is no password available.")
                continue

            LOG.info("The password server returned a valid password.")
            break

        return password

    def get_host_name(self):
        """Get the hostname for the server."""
        return self._get_meta_data().get("fqdn")

    def get_user_data(self):
        """Get the available user data for the current instance."""
        return self._get_meta_data().get("user_data")

    @property
    def can_post_password(self):
        """The HiBee metadata service does not support posting a password."""
        return False

    def get_network_details_v2(self):
        """Returns the network configuration in v2 format."""
        interfaces_config = self._get_meta_data().get("interfaces")
        if not interfaces_config:
            return

        links = self._get_network_links()
        if len(links) == 0:
            LOG.warning("No network links found from metadata service")
            return

        return network_model.NetworkDetailsV2(
            links=links,
            networks=self._get_network_networks(),
            services=self._get_network_services(),
        )

    def get_public_keys(self):
        """Returns public keys from meta data API"""
        return self._get_meta_data().get("public_keys", [])

    def _get_network_links(self):
        """Returns a list will all network links"""
        links = []

        interfaces_config = self._get_meta_data().get("interfaces")
        if not interfaces_config:
            return links

        LOG.debug(interfaces_config)

        i = 0
        for t in interfaces_config:
            i += 1
            nic = interfaces_config[t][0]

            link = network_model.Link(
                id='interface%s' % i,
                name="Network %s" % t,
                type=network_model.LINK_TYPE_PHYSICAL,
                enabled=True,
                mac_address=nic.get("mac"),
                mtu=nic.get("mtu", 1500),
                bond=None,
                vlan_link=None,
                vlan_id=None,
            )
            links.append(link)

        return links

    def _get_network_networks(self):
        """Returns the parsed networks"""
        networks = []

        interfaces_config = self._get_meta_data().get("interfaces")
        if not interfaces_config:
            return networks

        dns_config = self._get_meta_data().get("dns")
        if not dns_config:
            return networks

        i = 0
        for nic_type in interfaces_config:
            i += 1
            nic = interfaces_config[nic_type][0]

            for ip_version in ['ipv4', 'ipv6']:
                subnet = nic.get(ip_version, None)
                if not subnet:
                    continue

                if ip_version == 'ipv4':
                    default_gateway_cidr = "0.0.0.0/0"
                else:
                    default_gateway_cidr = "::/0"

                routes = []
                nameservers = []
                # Only the public interface has a gateway address
                # and nameservers
                if nic_type == "public":
                    routes.append(network_model.Route(
                        network_cidr=default_gateway_cidr,
                        gateway=subnet.get('gateway')
                    ))

                    nameservers = dns_config.get("nameservers", [])

                network = network_model.Network(
                    link='interface%s' % i,
                    address_cidr=network_utils.ip_netmask_to_cidr(
                        subnet.get('address'), subnet.get('netmask')
                    ),
                    routes=routes,
                    dns_nameservers=nameservers,
                )
                networks.append(network)

        return networks

    def _get_network_services(self):
        """Creates the name server service"""
        services = []

        dns_config = self._get_meta_data().get("dns")
        if not dns_config:
            return services

        services.append(network_model.NameServerService(
            addresses=dns_config.get("nameservers", []),
            search=None
        ))

        return services

    def _get_meta_data(self):
        """Requests the metadata from the metadata service and caches it."""
        return self._get_cache_data(
            "%s/v1.json" % CONF.hibee.metadata_base_url,
            decode=True
        )
